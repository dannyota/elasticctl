use super::super::*;
use super::apply::{FastClock, export_mock};
use super::plan::{pair, remote};
use super::reads::{FLAVORS, fixture, response, transport};
use super::requests::assert_import;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn imports_pack_utf8_bytes_and_lf_at_the_exact_boundary() {
    check_chunks(false).await;
}

#[tokio::test]
async fn uncertain_middle_import_leaves_the_later_chunk_not_sent() {
    check_chunks(true).await;
}

async fn check_chunks(uncertain: bool) {
    let flavor = FLAVORS[0];
    let first = format!("a{}", "é".repeat(3_999_998));
    let second = "c".repeat(7_999_999);
    let mut before = remote(flavor);
    before.container.container.list_type = ValueListType::Keyword;
    before.stored = StoredValues::default();
    let mut local = pair(&before);
    local.values = [first.clone(), "b".into(), second.clone(), "d".into()].into();
    let plan = plan_list(local, Some(before), &[], &[]).unwrap();
    let payloads = [format!("{first}\nb\n"), format!("{second}\n"), "d\n".into()];
    assert_eq!(payloads[0].len(), 8_000_000);
    assert_eq!(payloads[1].len(), 8_000_000);
    let server = MockServer::start().await;
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&count);
    let imported = fixture(flavor, "items_import");
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_import"))
        .and(query_param("list_id", &plan.local.container.id))
        .respond_with(move |_: &wiremock::Request| {
            let index = observed.fetch_add(1, Ordering::SeqCst);
            response(&imported, if uncertain && index == 1 { 503 } else { 200 })
        })
        .expect(if uncertain { 2 } else { 3 })
        .mount(&server)
        .await;
    export_mock(&server, flavor, "items_export", 200).await;
    let result = super::super::apply::apply_one(
        &transport(&server),
        &plan,
        &FastClock::default(),
        2,
        &mut None,
    )
    .await;
    assert_eq!(result.outcome, Outcome::Unknown);
    let writes: Vec<_> = result
        .evidence
        .iter()
        .filter(|e| e.action == Action::AddValues)
        .collect();
    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0].sent, Some(Sent::Accepted));
    assert_eq!(
        writes[1].sent,
        Some(if uncertain {
            Sent::Uncertain
        } else {
            Sent::Accepted
        })
    );
    assert_eq!(
        writes[2].sent,
        Some(if uncertain {
            Sent::NotSent
        } else {
            Sent::Accepted
        })
    );
    assert!(writes.iter().all(|entry| !entry.phase_verified));
    let requests = server.received_requests().await.unwrap();
    let imports: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().ends_with("_import"))
        .collect();
    let sent = if uncertain { 2 } else { 3 };
    assert_eq!(imports.len(), sent);
    assert_eq!(count.load(Ordering::SeqCst), sent);
    for (request, payload) in imports.iter().zip(&payloads) {
        assert_import(request, &plan.local.container.id, &plan.local.stem, payload);
    }
    assert!(requests.iter().skip(sent).all(|r| {
        super::requests::assert_request(
            r,
            "POST",
            "/api/lists/items/_export",
            &[("list_id", &plan.local.container.id)],
        );
        r.body.is_empty()
    }));
}
