use super::*;

#[derive(Default)]
pub(super) struct Stack {
    pub(super) lists: std::collections::BTreeMap<String, serde_json::Value>,
    pub(super) values: std::collections::BTreeMap<String, Vec<serde_json::Value>>,
    pub(super) exception: Option<serde_json::Value>,
    pub(super) item: Option<serde_json::Value>,
    pub(super) bootstrapped: bool,
    pub(super) fail: Option<&'static str>,
    pub(super) cleanup_refuses: bool,
    pub(super) deleted_item_reads: usize,
    pub(super) deleted_items: std::collections::BTreeMap<String, Vec<serde_json::Value>>,
    pub(super) flow_unavailable: bool,
    pub(super) late_list: Option<serde_json::Value>,
    pub(super) imported_pending: bool,
    pub(super) import_reads: u32,
    pub(super) pending_list: Option<String>,
    pub(super) created_by: Option<&'static str>,
}

pub(super) fn response(status: u16, body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(body)
}

impl Stack {
    fn answer(&mut self, request: &Request) -> ResponseTemplate {
        let path = request.url.path();
        let method = request.method.as_str();
        let query: std::collections::BTreeMap<_, _> =
            request.url.query_pairs().into_owned().collect();
        let id = query.get("id").cloned().unwrap_or_default();
        let list = query.get("list_id").cloned().unwrap_or_default();
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or(json!({}));
        match (method, path) {
            ("GET", p) if p.ends_with("/_search") => {
                let rows: Vec<_> = self
                    .values
                    .iter()
                    .chain(self.deleted_items.iter())
                    .filter(|(list, _)| list.starts_with(PREFIX))
                    .flat_map(|(list, values)| {
                        values.iter().map(move |v| {
                            json!({
                                "_id": v["id"], "_source": {"list_id": list}
                            })
                        })
                    })
                    .collect();
                if self.deleted_item_reads > 0 {
                    self.deleted_item_reads -= 1;
                    if self.deleted_item_reads == 0 {
                        self.deleted_items.clear();
                    }
                }
                response(
                    200,
                    json!({"timed_out": false, "_shards": {"failed": 0},
                    "hits": {"total": {"value": rows.len(), "relation": "eq"}, "hits": rows}}),
                )
            }
            ("GET", "/api/status") => response(
                200,
                json!({"version": {"number": "9.5.1", "build_flavor": "traditional"}}),
            ),
            ("GET", "/api/lists/index") => {
                if self.bootstrapped {
                    response(200, json!({"list_index": true, "list_item_index": true}))
                } else {
                    response(404, json!({}))
                }
            }
            ("POST", "/api/security_solution/initialize") if self.flow_unavailable => {
                response(404, json!({}))
            }
            ("POST", "/api/security_solution/initialize" | "/api/lists/index") => {
                self.bootstrapped = true;
                response(200, json!({}))
            }
            ("DELETE", "/api/lists/index") => {
                self.bootstrapped = false;
                response(200, json!({}))
            }
            ("GET", "/api/lists/_find") => {
                let rows: Vec<_> = self.lists.values().cloned().collect();
                if self.bootstrapped {
                    response(200, json!({"total": rows.len(), "data": rows}))
                } else {
                    response(404, json!({}))
                }
            }
            ("GET", "/api/exception_lists/_find") => {
                let rows: Vec<_> =
                    if query.get("namespace_type").map(String::as_str) == Some("single") {
                        self.exception.iter().cloned().collect()
                    } else {
                        vec![]
                    };
                response(200, json!({"total": rows.len(), "data": rows}))
            }
            ("GET", "/api/exception_lists/items/_find") => {
                let rows: Vec<_> = self.item.iter().cloned().collect();
                response(200, json!({"total": rows.len(), "data": rows}))
            }
            ("POST", "/api/lists") => {
                let key = body["id"].as_str().unwrap().to_string();
                let mut value = body;
                value["_version"] = json!("v1");
                if let Some(user) = self.created_by {
                    value["created_by"] = json!(user);
                }
                if self.fail == Some("late_create") {
                    self.late_list = Some(value);
                    return response(503, json!({}));
                }
                self.lists.insert(key, value.clone());
                if self.fail == Some("create") {
                    return response(400, json!({}));
                }
                response(200, value)
            }
            ("GET", "/api/lists") => {
                if let Some(late) = self.late_list.take() {
                    self.lists.insert(id.clone(), late);
                    return response(404, json!({}));
                }
                self.lists
                    .get(&id)
                    .cloned()
                    .map_or(response(404, json!({})), |v| response(200, v))
            }
            ("PATCH", "/api/lists") => {
                let value = self.lists.get_mut(body["id"].as_str().unwrap()).unwrap();
                if body["_version"] != value["_version"] {
                    if self.fail == Some("bad_status") {
                        return response(400, json!({"message": "private-body"}));
                    }
                    return response(
                        409,
                        json!({"status_code": 409,
                        "message": "stale version", "created_by": self.created_by.unwrap_or("private-user")}),
                    );
                }
                value["name"] = body["name"].clone();
                value["_version"] = json!("v2");
                response(200, value.clone())
            }
            ("PUT", "/api/lists") => {
                let value = self.lists.get(body["id"].as_str().unwrap()).unwrap();
                response(200, value.clone())
            }
            ("POST", "/api/lists/items") => {
                let key = body["list_id"].as_str().unwrap().to_string();
                let mut value = body;
                let text = value["value"].as_str().unwrap();
                if !text.contains('/') && !text.contains('-') {
                    value["value"] = json!(format!("{text}-{text}"));
                }
                self.values.entry(key).or_default().push(value.clone());
                response(200, value)
            }
            ("GET", "/api/lists/items/_find") => {
                if self.imported_pending && list == self.pending_list.as_deref().unwrap_or(LIST) {
                    self.import_reads += 1;
                    if self.import_reads >= 3 {
                        self.imported_pending = false;
                        let values = self.values.entry(list.clone()).or_default();
                        values.push(json!({"id": "server-import-1", "value": "10.0.0.8/32"}));
                        values.push(json!({"id": "server-import-2", "value": "10.0.0.9/32"}));
                    }
                }
                let values = self.values.get(&list).cloned().unwrap_or_default();
                let page: usize = query.get("page").unwrap().parse().unwrap();
                let per: usize = query.get("per_page").unwrap().parse().unwrap();
                if page > 1 && query.get("cursor").map(String::as_str) != Some("real-cursor") {
                    return response(400, json!({}));
                }
                let mut data: Vec<_> = values
                    .iter()
                    .skip((page - 1) * per)
                    .take(per)
                    .cloned()
                    .collect();
                if self.fail == Some("wrong_page") && page == 2 && !data.is_empty() {
                    data[0]["value"] = json!("10.99.0.1/32");
                }
                if self.fail == Some("wrong_item_id") && page == 1 && !data.is_empty() {
                    data[0]["id"] = json!("unexpected-id");
                }
                response(
                    200,
                    json!({"total": values.len(), "data": data, "cursor": "real-cursor"}),
                )
            }
            ("POST", "/api/lists/items/_export") => {
                let text: String = self
                    .values
                    .get(&list)
                    .into_iter()
                    .flatten()
                    .rev()
                    .map(|v| format!("{}\n", v["value"].as_str().unwrap()))
                    .collect();
                ResponseTemplate::new(200).set_body_string(text)
            }
            ("POST", "/api/lists/items/_import") => {
                if request.body.len() > 9_000_000 {
                    return response(
                        413,
                        json!({"status_code": 413,
                        "message": "file too large", "created_by": self.created_by.unwrap_or("private-user")}),
                    );
                }
                if String::from_utf8_lossy(&request.body).contains(".json\"")
                    && self.fail != Some("wrong_extension")
                {
                    return response(
                        415,
                        json!({"status_code": 415,
                        "message": "unsupported extension", "created_by": self.created_by.unwrap_or("private-user")}),
                    );
                }
                if !self.lists.contains_key(&list) {
                    return response(
                        409,
                        json!({"status_code": 409,
                        "message": "list does not exist", "created_by": self.created_by.unwrap_or("private-user")}),
                    );
                }
                self.imported_pending = true;
                self.import_reads = 0;
                self.pending_list = Some(list.clone());
                if self.fail == Some("import") {
                    return response(400, json!({}));
                }
                response(200, self.lists[&list].clone())
            }
            ("DELETE", "/api/lists/items") => {
                for values in self.values.values_mut() {
                    if let Some(index) = values.iter().position(|v| v["id"] == id) {
                        return response(200, values.remove(index));
                    }
                }
                response(
                    404,
                    json!({"message": format!("list item id: \"{id}\" not found"), "status_code": 404}),
                )
            }
            ("POST", "/api/exception_lists") => {
                let mut value = body;
                value["id"] = json!("server-exception-id");
                self.exception = Some(value.clone());
                response(200, value)
            }
            ("POST", "/api/exception_lists/items") => {
                if self.fail == Some("reference_rejected") {
                    return response(400, json!({}));
                }
                let mut value = body;
                value["id"] = json!("server-exception-item-id");
                self.item = Some(value.clone());
                if self.fail == Some("reference") {
                    return response(400, json!({}));
                }
                response(200, value)
            }
            ("GET", "/api/exception_lists") => self
                .exception
                .clone()
                .map_or(response(404, json!({})), |v| response(200, v)),
            ("GET", "/api/exception_lists/items") => self
                .item
                .clone()
                .map_or(response(404, json!({})), |v| response(200, v)),
            ("DELETE", "/api/exception_lists/items") if !self.cleanup_refuses => {
                response(200, self.item.take().unwrap())
            }
            ("DELETE", "/api/exception_lists") if !self.cleanup_refuses => {
                response(200, self.exception.take().unwrap())
            }
            ("DELETE", "/api/lists") if self.item.is_some() && id == LIST => {
                response(409, json!({"references": [self.item.clone().unwrap()]}))
            }
            ("DELETE", "/api/lists") if !self.cleanup_refuses => {
                if let Some(values) = self.values.remove(&id)
                    && self.deleted_item_reads > 0
                {
                    self.deleted_items.insert(id.clone(), values);
                }
                self.lists
                    .remove(&id)
                    .map_or(response(404, json!({})), |v| response(200, v))
            }
            _ => response(400, json!({})),
        }
    }
}

pub(super) async fn stack(state: Stack) -> (MockServer, Arc<Mutex<Stack>>) {
    let server = MockServer::start().await;
    let state = Arc::new(Mutex::new(state));
    let fake = state.clone();
    Mock::given(wiremock::matchers::any())
        .respond_with(move |request: &Request| fake.lock().unwrap().answer(request))
        .mount(&server)
        .await;
    (server, state)
}
