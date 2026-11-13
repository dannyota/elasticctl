use super::super::*;
use super::apply::{FastClock, mount_items};
use super::plan::{pair, reference, remote};
use super::reads::{FLAVORS, fixture, response, transport};
use super::requests::assert_plan_writes;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn adds_first_enumeration_disagreement_stops_after_the_verified_add_before_any_delete() {
    for flavor in FLAVORS {
        let export = fixture(flavor, "export_spellings");
        let mut before = remote(flavor);
        before.stored = decode_export(
            &before.container.container.list_type,
            export["response"].as_str().unwrap(),
        )
        .unwrap();
        let mut local = pair(&before);
        local.values.pop_first();
        let added = local.values.last().unwrap().clone();
        before.stored.values.retain(|value| value != &added);
        let consumer = reference(&local.container.id, ReferenceOperator::Excluded);
        let plan = plan_list(local, Some(before), &[consumer], &[]).unwrap();
        assert_eq!(plan.order, PhaseOrder::AddsFirst);
        assert_eq!(plan.adds, [added.clone()].into());
        assert_eq!(plan.removes.len(), 1);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_import"))
            .and(query_param("list_id", &plan.local.container.id))
            .respond_with(response(&fixture(flavor, "items_import"), 200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .and(query_param("list_id", &plan.local.container.id))
            .respond_with(response(&export, 200))
            .expect(1)
            .mount(&server)
            .await;
        mount_items(&server, flavor).await;
        let result = super::super::apply::apply_one(
            &transport(&server),
            &plan,
            &FastClock::default(),
            2,
            &mut None,
        )
        .await;
        assert_plan_writes(&server, flavor, &plan).await;
        assert_eq!(result.outcome, Outcome::Failed);
        assert_eq!(result.error.unwrap().kind, "conflict");
        assert_eq!(result.evidence[0].sent, Some(Sent::Accepted));
        assert!(result.evidence[0].phase_verified);
        assert_eq!(result.evidence[1].sent, Some(Sent::NotSent));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].url.path(), "/api/lists/items/_import");
        assert_eq!(requests[1].url.path(), "/api/lists/items/_export");
        let content_type = requests[0].headers["content-type"].to_str().unwrap();
        let boundary = content_type
            .strip_prefix("multipart/form-data; boundary=")
            .unwrap();
        assert_eq!(
            requests[0].body,
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}.txt\"\r\nContent-Type: text/plain\r\n\r\n{added}\n\r\n--{boundary}--\r\n",
                plan.local.stem
            ).into_bytes()
        );
        assert_eq!(requests[0].url.query_pairs().count(), 1);
        assert_eq!(requests[1].url.query_pairs().count(), 1);
        assert_eq!(requests[2].url.query_pairs().count(), 3);
        assert_eq!(requests[3].url.query_pairs().count(), 4);
        assert!(requests.iter().skip(1).all(|r| r.body.is_empty()));
        assert!(requests.iter().all(|r| r.method != "DELETE"));
    }
}

#[tokio::test]
async fn item_cursor_pages_equal_the_export_as_a_multiset_on_every_stack() {
    for flavor in FLAVORS {
        let server = MockServer::start().await;
        mount_items(&server, flavor).await;
        let first = fixture(flavor, "items_find_first");
        let id = first["request"]["list_id"].as_str().unwrap();
        let items = super::super::reads::find_cursor(
            &transport(&server),
            &format!(
                "/api/lists/items/_find?list_id={}",
                elasticctl_core::urlencode(id)
            ),
            first["request"]["per_page"].as_u64().unwrap() as u32,
        )
        .await
        .unwrap();
        let mut actual: Vec<_> = items
            .iter()
            .map(|item| item["value"].as_str().unwrap())
            .collect();
        actual.sort();
        let export = fixture(flavor, "items_export");
        let mut expected: Vec<_> = export["response"].as_str().unwrap().lines().collect();
        expected.sort();
        assert_eq!(actual, expected);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].url.query_pairs().count(), 3);
        assert_eq!(requests[1].url.query_pairs().count(), 4);
        assert!(requests.iter().all(|r| r.body.is_empty()));
    }
}
