use elasticctl_core::{ErrorKind, Profile, Transport, TransportOptions};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Clone, Copy)]
enum Reply {
    Ok,
    Close,
    Drop,
    Status(u16),
}

struct Server {
    url: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
    close: Arc<tokio::sync::Notify>,
    closed: Arc<tokio::sync::Notify>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let c = connections.clone();
        let r = requests.clone();
        let close = Arc::new(tokio::sync::Notify::new());
        let closed = Arc::new(tokio::sync::Notify::new());
        let signal = close.clone();
        let done = closed.clone();
        let replies = Arc::new(replies);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                c.fetch_add(1, Ordering::SeqCst);
                let r = r.clone();
                let replies = replies.clone();
                let signal = signal.clone();
                let done = done.clone();
                tokio::spawn(async move {
                    loop {
                        let mut header = Vec::new();
                        loop {
                            let mut byte = [0];
                            if stream.read_exact(&mut byte).await.is_err() {
                                return;
                            }
                            header.push(byte[0]);
                            if header.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        let text = String::from_utf8(header).unwrap();
                        assert!(text.lines().next().unwrap().ends_with("HTTP/1.1"));
                        let len = text
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        let mut body = vec![0; len];
                        stream.read_exact(&mut body).await.unwrap();
                        let index = r.fetch_add(1, Ordering::SeqCst);
                        let reply = *replies.get(index).unwrap_or(&Reply::Ok);
                        if matches!(reply, Reply::Drop) {
                            return;
                        }
                        let status = match reply {
                            Reply::Status(s) => s,
                            _ => 200,
                        };
                        let response = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        if matches!(reply, Reply::Close) {
                            signal.notified().await;
                            drop(stream);
                            done.notify_one();
                            return;
                        }
                    }
                });
            }
        });
        Self {
            url,
            connections,
            requests,
            task,
            close,
            closed,
        }
    }
    fn counts(&self) -> (usize, usize) {
        (
            self.connections.load(Ordering::SeqCst),
            self.requests.load(Ordering::SeqCst),
        )
    }
    fn profile(&self) -> Profile {
        Profile {
            kibana_url: self.url.clone(),
            es_url: None,
            api_key: Some("test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 5,
        }
    }
}
fn options(disable_pool: bool) -> TransportOptions {
    TransportOptions {
        disable_redirects: true,
        disable_retries: true,
        disable_connection_pool: disable_pool,
        ..Default::default()
    }
}
async fn write(t: &Transport, patch: bool) -> elasticctl_core::Result<serde_json::Value> {
    if patch {
        t.patch("/", &json!({"a": 1})).await
    } else {
        t.post("/", Some(&json!({"a": 1}))).await
    }
}

#[tokio::test]
async fn closed_after_get_then_write() {
    // Without a pool the write always gets a fresh socket and succeeds. With
    // the pool, the write may land on the socket the peer closed: it then
    // fails as a connection error after one request and is never replayed,
    // or the client notices the close first and opens a new connection.
    for disable_pool in [true, false] {
        for patch in [false, true] {
            let s = Server::start(vec![Reply::Close, Reply::Ok]).await;
            let t = Transport::with_options(&s.profile(), options(disable_pool)).unwrap();
            t.get("/").await.unwrap();
            s.close.notify_one();
            tokio::time::timeout(std::time::Duration::from_secs(2), s.closed.notified())
                .await
                .unwrap();
            let result = write(&t, patch).await;
            match result {
                Ok(_) => assert_eq!(s.counts(), (2, 2)),
                Err(error) => {
                    assert!(!disable_pool, "a write without a pool must succeed");
                    assert_eq!(error.kind, ErrorKind::Connection);
                    assert_eq!(s.counts(), (1, 1));
                }
            }
        }
    }
}
#[tokio::test]
async fn dropped_write_is_not_replayed() {
    for disable_pool in [true, false] {
        for patch in [false, true] {
            let s = Server::start(vec![Reply::Drop]).await;
            let t = Transport::with_options(&s.profile(), options(disable_pool)).unwrap();
            assert_eq!(
                write(&t, patch).await.unwrap_err().kind,
                ErrorKind::Connection
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert_eq!(
                s.counts(),
                (1, 1),
                "disable_pool={disable_pool}, patch={patch}"
            );
        }
    }
}
#[tokio::test]
async fn transient_status_is_returned_once() {
    for status in [429, 503] {
        let s = Server::start(vec![Reply::Status(status)]).await;
        let t = Transport::with_options(&s.profile(), options(true)).unwrap();
        assert_eq!(
            write(&t, false).await.unwrap_err().http_status,
            Some(status)
        );
        assert_eq!(s.counts(), (1, 1));
    }
}
#[tokio::test]
async fn disabled_pool_opens_two_connections() {
    let s = Server::start(vec![Reply::Ok, Reply::Ok]).await;
    let t = Transport::with_options(&s.profile(), options(true)).unwrap();
    t.get("/").await.unwrap();
    t.get("/").await.unwrap();
    assert_eq!(s.counts(), (2, 2));
}
#[tokio::test]
async fn existing_constructors_and_mcp_options_reuse_connections() {
    for mode in 0..4 {
        let s = Server::start(vec![Reply::Ok, Reply::Ok]).await;
        let p = s.profile();
        let t = match mode {
            0 => Transport::new(&p).unwrap(),
            1 => Transport::with_debug(&p, false).unwrap(),
            _ => Transport::with_options(
                &p,
                TransportOptions {
                    response_body_limit: Some(16 * 1024 * 1024),
                    disable_redirects: true,
                    disable_retries: mode == 2,
                    disable_connection_pool: false,
                    ..Default::default()
                },
            )
            .unwrap(),
        };
        t.get("/").await.unwrap();
        t.get("/").await.unwrap();
        assert_eq!(s.counts(), (1, 2), "mode {mode}");
    }
}
