use crate::cli::{Cli, ValueListsAction};
use crate::context::Context;
use crate::guard::{ValueListPreview, check_value_lists};
use crate::render;
use elasticctl_api::value_lists::{self as api, Failure, ImportPreview, MutationReport};
use elasticctl_core::{Error, ErrorKind, Result};
use serde::Serialize;
use serde_json::{Value, json};

fn value<T: Serialize>(report: T) -> Result<Value> {
    serde_json::to_value(report)
        .map_err(|error| Error::new(ErrorKind::Error, format!("encoding report: {error}")))
}

#[derive(Serialize)]
struct DeleteTarget<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    list_type: &'a api::ValueListType,
}

pub(crate) async fn value_lists(args: &Cli, action: &ValueListsAction) -> Result<Value> {
    if let ValueListsAction::Validate { path } = action {
        return value(api::validate_path(path)?);
    }
    let local = match action {
        ValueListsAction::Import { path, .. } => Some(api::read_pair(path)?),
        _ => None,
    };
    let ctx = Context::build(&args.global)?;
    ctx.require_credential()?;
    let t = ctx.transport().await?;
    match action {
        ValueListsAction::List { list_type, search } => {
            let kind = list_type.map(Into::into);
            value(api::list_op(t, kind.as_ref(), search.as_deref()).await?)
        }
        ValueListsAction::Get { id, values } => value(api::get_op(t, id, *values).await?),
        ValueListsAction::Export { ids, dir } => value(
            api::export_op(
                t,
                ids,
                dir.as_deref(),
                ctx.global.json,
                ctx.global.out.as_deref(),
            )
            .await?,
        ),
        ValueListsAction::Import { overwrite, .. } => {
            let plan = api::plan_import(t, local.expect("import pair"), *overwrite).await?;
            let lists = [ImportPreview::from(&plan)];
            if !check_value_lists(
                &ctx,
                &ValueListPreview::new(&ctx, "value-lists import", &lists),
            )? {
                return Ok(json!({"applied": false, "total": 1}));
            }
            let report = MutationReport::import(
                api::apply_plans(t, &[plan], &api::SystemClock::default()).await,
            );
            let error = report.lists.iter().find_map(|r| r.error.as_ref());
            finish(&ctx, &report, error)
        }
        ValueListsAction::Delete { ids } => {
            let plan = api::plan_delete(t, ids).await?;
            let lists: Vec<_> = plan
                .before
                .iter()
                .map(|r| DeleteTarget {
                    id: &r.container.container.id,
                    list_type: &r.container.container.list_type,
                })
                .collect();
            if !check_value_lists(
                &ctx,
                &ValueListPreview::new(&ctx, "value-lists delete", &lists),
            )? {
                return Ok(json!({"applied": false, "total": lists.len()}));
            }
            let report = MutationReport::delete(api::apply_delete(t, &plan).await);
            let error = report.lists.iter().find_map(|r| r.result.error.as_ref());
            finish(&ctx, &report, error)
        }
        ValueListsAction::Init => {
            let ready = api::bootstrap_state(t).await?.ready();
            let mut preview = ValueListPreview::<Value>::new(&ctx, "value-lists init", &[]);
            preview.flow = Some("create-list-indices");
            preview.already_bootstrapped = Some(ready);
            let apply = check_value_lists(&ctx, &preview)?;
            if ready {
                return Ok(
                    json!({"applied": false, "outcome": "already_bootstrapped", "message": "already bootstrapped"}),
                );
            }
            if !apply {
                return Ok(json!({"applied": false}));
            }
            value(json!({"applied": true, "outcome": api::apply_init(t).await?}))
        }
        ValueListsAction::Validate { .. } => unreachable!(),
    }
}

fn finish<T: Serialize>(ctx: &Context, report: &T, failure: Option<&Failure>) -> Result<Value> {
    let report = value(report)?;
    if let Some(failure) = failure {
        render::emit(&report, &ctx.global)?;
        let kind = match failure.kind.as_str() {
            "auth" => ErrorKind::Auth,
            "permission" => ErrorKind::Permission,
            "not_found" => ErrorKind::NotFound,
            "conflict" => ErrorKind::Conflict,
            "unsupported" => ErrorKind::Unsupported,
            "http" => ErrorKind::Http,
            "connection" => ErrorKind::Connection,
            "timeout" => ErrorKind::Timeout,
            _ => ErrorKind::Error,
        };
        return Err(Error {
            kind,
            http_status: failure.status,
            message: failure.message.clone(),
        });
    }
    Ok(report)
}
