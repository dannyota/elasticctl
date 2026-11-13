use super::super::read_back::{Expected, settle};
use super::super::*;
use super::apply::{FastClock, export_mock};
use super::plan::remote;
use super::reads::{FLAVORS, fixture, response, transport};
use std::time::Duration;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn phase_exports_remain_a_second_apart_across_phase_boundaries() {
    let flavor = FLAVORS[0];
    let remote = remote(flavor);
    let server = MockServer::start().await;
    export_mock(&server, flavor, "items_export", 200).await;
    let clock = FastClock::default();
    let mut last_end = None;
    let expected = remote.stored.set();
    for _ in 0..2 {
        let result = settle(
            &transport(&server),
            &remote.container.container,
            Expected::Values(&expected),
            &clock,
            &mut last_end,
        )
        .await;
        assert!(result.verified);
    }
    assert_eq!(clock.now(), Duration::from_secs(1));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn read_back_retries_exports_until_the_expected_set_is_observed() {
    let flavor = FLAVORS[0];
    let remote = remote(flavor);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(response(&fixture(flavor, "export_spellings"), 200))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    export_mock(&server, flavor, "items_export", 200).await;
    let clock = FastClock::default();
    let mut last_end = None;
    let result = settle(
        &transport(&server),
        &remote.container.container,
        Expected::Values(&remote.stored.set()),
        &clock,
        &mut last_end,
    )
    .await;
    assert!(result.verified);
    assert_eq!(clock.now(), Duration::from_secs(2));
    assert_eq!(result.stored.unwrap(), remote.stored);
}

struct AlmostSpent(std::sync::atomic::AtomicUsize);
impl Clock for AlmostSpent {
    fn now(&self) -> Duration {
        if self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
            Duration::ZERO
        } else {
            Duration::from_millis(119_990)
        }
    }
    fn pause(
        &self,
        _: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        panic!("no pause fits the remaining budget")
    }
}

#[tokio::test]
async fn a_slow_export_is_cancelled_at_the_remaining_budget() {
    let flavor = FLAVORS[0];
    let remote = remote(flavor);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(
            response(&fixture(flavor, "items_export"), 200).set_delay(Duration::from_millis(200)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let clock = AlmostSpent(std::sync::atomic::AtomicUsize::new(0));
    let start = std::time::Instant::now();
    let result = settle(
        &transport(&server),
        &remote.container.container,
        Expected::Values(&remote.stored.set()),
        &clock,
        &mut None,
    )
    .await;
    assert!(!result.verified);
    assert_eq!(result.evidence.observed, Some(false));
    assert_eq!(result.evidence.read_error.unwrap().kind, "timeout");
    assert!(start.elapsed() < Duration::from_millis(200));
}

#[tokio::test]
async fn default_transport_export_retries_are_at_least_one_second_apart() {
    use elasticctl_core::{Profile, Transport};
    use std::sync::{Arc, Mutex};
    let flavor = FLAVORS[0];
    let remote = remote(flavor);
    let server = MockServer::start().await;
    let times = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&times);
    let export = fixture(flavor, "items_export");
    Mock::given(method("POST"))
        .and(path("/api/lists/items/_export"))
        .respond_with(move |_: &wiremock::Request| {
            let mut times = captured.lock().unwrap();
            times.push(std::time::Instant::now());
            response(&export, if times.len() == 1 { 503 } else { 200 })
        })
        .expect(2)
        .mount(&server)
        .await;
    let t = Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("synthetic".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 2,
    })
    .unwrap();
    let result = settle(
        &t,
        &remote.container.container,
        Expected::Values(&remote.stored.set()),
        &SystemClock::default(),
        &mut None,
    )
    .await;
    assert!(result.verified);
    let times = times.lock().unwrap();
    assert!(times[1].duration_since(times[0]) >= Duration::from_secs(1));
}

#[tokio::test]
async fn containment_read_back_waits_until_only_the_target_item_leaves() {
    for flavor in FLAVORS {
        let container = decode_remote_container(&fixture(flavor, "contain_create")["response"])
            .unwrap()
            .container;
        let before = fixture(flavor, "contain_export");
        let after = fixture(flavor, "contain_export_after");
        let deleted = fixture(flavor, "contain_delete_id");
        let expected: ValueSet = after["response"]
            .as_str()
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let mut stored_before: Vec<_> = before["response"]
            .as_str()
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        stored_before.sort();
        let mut expected_before: Vec<_> = expected.iter().cloned().collect();
        expected_before.push(deleted["response"]["value"].as_str().unwrap().to_owned());
        expected_before.sort();
        assert_eq!(stored_before, expected_before);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .and(query_param("list_id", &container.id))
            .respond_with(response(&before, 200))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .and(query_param("list_id", &container.id))
            .respond_with(response(&after, 200))
            .expect(1)
            .mount(&server)
            .await;
        let clock = FastClock::default();
        let result = settle(
            &transport(&server),
            &container,
            Expected::Values(&expected),
            &clock,
            &mut None,
        )
        .await;
        assert!(result.verified);
        let mut observed = result.stored.unwrap().values;
        observed.sort();
        assert_eq!(observed, expected.into_iter().collect::<Vec<_>>());
        assert_eq!(result.evidence.observed, Some(true));
        assert_eq!(result.evidence.missing, Some(0));
        assert_eq!(result.evidence.extra, Some(0));
        assert_eq!(clock.now(), Duration::from_secs(1));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.body.is_empty()
            && r.url.query_pairs().count() == 1
            && !r.url.query_pairs().any(|(key, _)| key == "value")));
    }
}
