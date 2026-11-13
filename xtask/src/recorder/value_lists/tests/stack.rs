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
                if !self.bootstrapped {
                    return response(404, json!({}));
                }
                let rows: Vec<_> = self
                    .lists
                    .values()
                    .filter(|row| {
                        query.get("filter").is_none_or(|filter| {
                            filter
                                .strip_prefix("name:")
                                .and_then(|v| v.strip_suffix('*'))
                                .is_some_and(|prefix| {
                                    row["name"]
                                        .as_str()
                                        .is_some_and(|name| name.starts_with(prefix))
                                })
                        })
                    })
                    .cloned()
                    .collect();
                let page: usize = query.get("page").map_or(1, |v| v.parse().unwrap());
                let per: usize = query.get("per_page").map_or(100, |v| v.parse().unwrap());
                if page > 1 && query.get("cursor").map(String::as_str) != Some("real-cursor") {
                    return response(400, json!({}));
                }
                let data: Vec<_> = rows
                    .iter()
                    .skip((page - 1) * per)
                    .take(per)
                    .cloned()
                    .collect();
                response(
                    200,
                    json!({"total": rows.len(), "data": data, "page": page, "per_page": per, "cursor": "real-cursor"}),
                )
            }
            ("GET", "/api/exception_lists/_find") => {
                if self.fail == Some("exception_lists_find") && query.contains_key("filter") {
                    return response(503, json!({"message":"private-body"}));
                }
                let rows: Vec<_> =
                    if query.get("namespace_type").map(String::as_str) == Some("single") {
                        self.exception
                            .iter()
                            .filter(|row| {
                                query.get("filter").is_none_or(|filter| {
                                    filter
                                        .strip_prefix("exception-list.attributes.list_id:")
                                        .and_then(|v| v.strip_suffix('*'))
                                        .is_some_and(|prefix| {
                                            row["list_id"]
                                                .as_str()
                                                .is_some_and(|id| id.starts_with(prefix))
                                        })
                                })
                            })
                            .cloned()
                            .collect()
                    } else {
                        vec![]
                    };
                if query.get("namespace_type").map(String::as_str) == Some("agnostic")
                    && query.get("filter").is_some_and(|filter| {
                        !filter.starts_with("exception-list-agnostic.attributes.")
                    })
                {
                    return response(
                        400,
                        json!({"message": "This type exception-list is not allowed: Bad Request", "status_code": 400}),
                    );
                }
                if self.fail == Some("agnostic_nonempty")
                    && query.get("namespace_type").map(String::as_str) == Some("agnostic")
                    && query.get("per_page").map(String::as_str) == Some("10000")
                {
                    return response(
                        200,
                        json!({"total": 1, "data": [{"list_id": "unexpected"}]}),
                    );
                }
                response(200, json!({"total": rows.len(), "data": rows}))
            }
            ("GET", "/api/exception_lists/items/_find") => {
                if self.fail == Some("exception_items_find")
                    && query.get("per_page").map(String::as_str) == Some("10")
                {
                    return response(503, json!({"message":"private-body"}));
                }
                let mut rows: Vec<_> = self.item.iter().cloned().collect();
                if query.get("per_page").map(String::as_str) == Some("10") && !rows.is_empty() {
                    if self.fail == Some("missing_operator") {
                        rows[0]["entries"][1]
                            .as_object_mut()
                            .unwrap()
                            .remove("operator");
                    }
                    if self.fail == Some("changed_operator") {
                        rows[0]["entries"][1]["operator"] = json!("included");
                    }
                }
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
                self.lists.insert(key.clone(), value.clone());
                if key == CONTAIN && self.fail == Some("contain_create") {
                    return response(503, json!({"message":"private-body"}));
                }
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
                self.values
                    .entry(key.clone())
                    .or_default()
                    .push(value.clone());
                if key == CONTAIN
                    && ((self.fail == Some("contain_add_item_0")
                        && value["id"] == format!("{CONTAIN}-item-0"))
                        || (self.fail == Some("contain_add_item_1")
                            && value["id"] == format!("{CONTAIN}-item-1")))
                {
                    return response(503, json!({"message":"private-body"}));
                }
                response(200, value)
            }
            ("GET", "/api/lists/items/_find") => {
                if self.imported_pending && list == self.pending_list.as_deref().unwrap_or(LIST) {
                    self.import_reads += 1;
                    if self.import_reads >= 3 {
                        self.imported_pending = false;
                        let values = self.values.entry(list.clone()).or_default();
                        if list == CONTAIN {
                            values.push(json!({"id": "server-import-3", "value": "10.0.0.6/32"}));
                        } else {
                            values.push(json!({"id": "server-import-1", "value": "10.0.0.8/32"}));
                            values.push(json!({"id": "server-import-2", "value": "10.0.0.9/32"}));
                        }
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
                if list == CONTAIN {
                    let count = self.values.get(&list).map_or(0, Vec::len);
                    if (self.fail == Some("contain_export") && count == 2)
                        || (self.fail == Some("contain_export_after")
                            && count == 1
                            && self.values[&list][0]["value"] == "10.0.0.0/8")
                    {
                        return response(503, json!({"message":"private-body"}));
                    }
                    if self.fail == Some("contain_missing_range")
                        && count == 1
                        && self.values[&list][0]["value"] == "10.0.0.0/8"
                    {
                        return ResponseTemplate::new(200).set_body_string("");
                    }
                }
                if list == LIST
                    && self.fail == Some("delete_duplicate")
                    && self.values.get(&list).is_some_and(|v| v.len() == 2)
                {
                    return ResponseTemplate::new(200)
                        .set_body_string("10.0.0.6/32\n10.0.0.6/32\n");
                }
                if list == CONTAIN
                    && self.fail == Some("import_missing_range")
                    && self
                        .values
                        .get(&list)
                        .is_some_and(|v| v.iter().any(|x| x["value"] == "10.0.0.6/32"))
                {
                    return ResponseTemplate::new(200).set_body_string("10.0.0.6/32\n");
                }
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
                if id == format!("{CONTAIN}-item-0") && self.fail == Some("contain_delete_id") {
                    return response(400, json!({"message":"private-body"}));
                }
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
                let references = json!([{
                    "exception_item": self.item.clone().unwrap(),
                    "exception_list": self.exception.clone().unwrap(),
                }]);
                response(
                    409,
                    json!({"message": {"error": {
                        "message": "value list is referenced", "references": references,
                    }}, "status_code": 409}),
                )
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
