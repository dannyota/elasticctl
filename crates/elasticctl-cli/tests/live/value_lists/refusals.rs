use super::round_trip::RoundTrip;
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Refusal {
    Missing,
    TypeMismatch,
}

pub(super) fn dash_refusal(nonce: &str) -> StepResult {
    let id = format!("{PREFIX}{nonce}-local-dash-refusal");
    let pair = api::LocalPair {
        stem: api::file_stem(&id),
        container: api::Container {
            id: id.clone(),
            list_type: api::ValueListType::IpRange,
            name: id,
            description: LIVE_TAG.into(),
            meta: None,
        },
        values: (0..201).map(|n| format!("10.1.{n}.1-10.1.{n}.2")).collect(),
    };
    let Err(error) = api::plan_list(pair, None, &[], &[]) else {
        return Err(StepError::Failed);
    };
    require(
        error.kind == ErrorKind::Unsupported
            && error.message.contains("201")
            && error.message.contains("200"),
    )
}

pub(super) async fn one(
    t: &Transport,
    lease: &Lease,
    run: &RoundTrip<'_>,
    case: Refusal,
) -> StepResult {
    lease.check_interrupt()?;
    let before = run.snapshot(t, lease).await?;
    let mirror = run.mirror()?;
    let (path, body, expected_id, kind) = match case {
        Refusal::Missing => {
            require(mirror.lists.len() == 1)?;
            let container = mirror.lists[0].list_id().map_err(|_| StepError::Failed)?;
            let path = run
                .dir
                .join("exceptions")
                .join(format!("{container}.ndjson"));
            let bytes = std::fs::read(&path).map_err(|_| StepError::Failed)?;
            let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| StepError::Failed)?;
            let missing = format!("{}-missing", run.ip);
            let mut changed = 0;
            for item in value["items"].as_array_mut().ok_or(StepError::Failed)? {
                for entry in item["entries"].as_array_mut().ok_or(StepError::Failed)? {
                    if entry["type"] == "list" && entry["list"]["id"] == run.ip {
                        entry["list"]["id"] = json!(missing);
                        changed += 1;
                    }
                }
            }
            require(changed > 0)?;
            (
                path,
                serde_json::to_vec(&value).map_err(|_| StepError::Failed)?,
                missing,
                "not_found",
            )
        }
        Refusal::TypeMismatch => {
            let path = run.values_path(&run.ip).with_extension("yaml");
            let mut container = checked_step(api::read_pair(&path))?.container;
            require(container.list_type == api::ValueListType::IpRange)?;
            container.list_type = api::ValueListType::Keyword;
            (
                path,
                checked_step(api::encode_container(&container))?.into_bytes(),
                run.ip.clone(),
                "conflict",
            )
        }
    };
    let original = std::fs::read(&path).map_err(|_| StepError::Failed)?;
    std::fs::write(&path, body).map_err(|_| StepError::Failed)?;
    let result = (|| {
        lease.check_interrupt()?;
        let output = run
            .state_command("push")
            .output()
            .map_err(|_| StepError::Failed)?;
        require(!output.status.success())?;
        let error: Value = serde_json::from_slice(&output.stderr).map_err(|_| StepError::Failed)?;
        require(
            error["error"]["kind"] == kind
                && error["error"]["message"]
                    .as_str()
                    .is_some_and(|s| s.contains(&expected_id)),
        )
    })();
    let restored = std::fs::write(&path, original).map_err(|_| StepError::Failed);
    let unchanged = run.snapshot(t, lease).await.map(|after| after == before);
    restored?;
    require(unchanged?)?;
    result
}

pub(super) async fn run(t: &Transport, lease: &Lease, run: &RoundTrip<'_>) -> StepResult {
    one(t, lease, run, Refusal::Missing).await?;
    one(t, lease, run, Refusal::TypeMismatch).await?;
    lease.check_interrupt()?;
    dash_refusal(&lease.nonce)
}
