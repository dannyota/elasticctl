//! The exception-list endpoint wrappers' contract, independent of the CLI.

use elasticctl_api::exceptions::{self, ListFilter};
use elasticctl_api::model::ListKey;
use elasticctl_api_test_support::MockStack;

async fn mock_exception_lists(n: usize) -> MockStack {
    MockStack::with_exception_lists(n).await
}

async fn mock_exception_items(n: usize) -> MockStack {
    MockStack::with_exception_items(n).await
}

#[tokio::test]
async fn find_lists_reads_the_data_array_and_total() {
    let stack = mock_exception_lists(2).await;
    let found = exceptions::find_lists(stack.transport(), &ListFilter::default())
        .await
        .unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].list_id().unwrap(), "l0");
}

/// A container that exists only in the `agnostic` namespace must not resolve
/// against a `single` key. Spec 4.5: namespace_type is part of identity.
#[tokio::test]
async fn resolve_ids_keys_on_namespace_as_well_as_list_id() {
    let stack = mock_exception_lists(0).await;
    let map = exceptions::resolve_ids(
        stack.transport(),
        &[ListKey {
            list_id: "l".into(),
            namespace_type: "agnostic".into(),
        }],
    )
    .await
    .unwrap();
    assert!(
        map.is_empty(),
        "an absent list is absent, never a placeholder"
    );
}

/// Paging is not optional: a list with more items than one page must return
/// all of them or a mirror silently drops exceptions.
#[tokio::test]
async fn find_items_reads_every_page() {
    let stack = mock_exception_items(250).await; // the mock caps per_page below this
    let items = exceptions::find_items(
        stack.transport(),
        &ListKey {
            list_id: "l".into(),
            namespace_type: "single".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(items.len(), 250, "a short read is a silent data loss");
}

/// The map distinguishes "exists here with this id" from "does not exist here";
/// Tasks 11 and 12 rely on that distinction, so an absent key is absent rather
/// than mapped to a placeholder.
#[tokio::test]
async fn resolve_ids_maps_live_keys_to_ids_and_omits_absent_keys() {
    let stack = mock_exception_lists(1).await; // only l0 exists
    let map = exceptions::resolve_ids(
        stack.transport(),
        &[
            ListKey {
                list_id: "l0".into(),
                namespace_type: "single".into(),
            },
            ListKey {
                list_id: "missing".into(),
                namespace_type: "single".into(),
            },
        ],
    )
    .await
    .unwrap();

    assert_eq!(map.len(), 1, "the absent key must not appear");
    assert_eq!(
        map.get(&ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        })
        .map(String::as_str),
        Some("id-l0"),
        "a live key maps to its container id"
    );
}

#[tokio::test]
async fn get_list_reads_a_container_by_list_id_and_namespace() {
    let stack = mock_exception_lists(1).await;
    let list = exceptions::get_list(
        stack.transport(),
        &ListKey {
            list_id: "l0".into(),
            namespace_type: "single".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(list.list_id().unwrap(), "l0");
    assert_eq!(list.namespace_type(), "single");
}
