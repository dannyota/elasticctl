#[allow(dead_code)]
mod support;

use elasticctl_core::{Profile, Resolved, Source};
use elasticctl_mcp::ServerOptions;
use rmcp::{
    ClientLifecycleMode, ClientServiceExt, RoleClient, model::ProtocolVersion,
    transport::async_rw::AsyncRwTransport,
};
use support::EXPECTED_TOOL_NAMES;

fn target() -> Resolved {
    Resolved {
        name: "test".to_string(),
        source: Source::Profile,
        profile: Profile {
            kibana_url: "https://kibana.example.test/base".to_string(),
            es_url: Some("https://es.example.test/base".to_string()),
            api_key: None,
            username: None,
            password: None,
            space: "default".to_string(),
            verify: true,
            timeout_secs: 30,
        },
    }
}

#[tokio::test]
async fn sdk_client_discovers_and_lists_the_current_catalog() {
    let (client_write, server_read) = tokio::io::duplex(16_384);
    let (server_write, client_read) = tokio::io::duplex(16_384);
    let server = tokio::spawn(elasticctl_mcp::serve_io(
        target(),
        ServerOptions::default(),
        server_read,
        server_write,
    ));
    let transport = AsyncRwTransport::<RoleClient, _, _>::new_client(client_read, client_write);
    let client = ()
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("SDK client completes current discovery");
    let listed = client
        .list_tools(None)
        .await
        .expect("SDK client lists tools after discovery");
    let names = listed
        .tools
        .iter()
        .map(|tool| tool.name.as_ref())
        .collect::<Vec<_>>();
    assert_eq!(names, EXPECTED_TOOL_NAMES);
    client.cancel().await.expect("SDK client closes cleanly");
    server
        .await
        .expect("server task does not panic")
        .expect("server shuts down cleanly");
}
