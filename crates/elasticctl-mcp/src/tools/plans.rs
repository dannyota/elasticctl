//! Stored plan tool definitions and adapters.
use std::{future::Future, pin::Pin, sync::Arc};

use elasticctl_core::{Error, ErrorKind};
use rmcp::{
    model::{JsonObject, Tool, ToolAnnotations},
    schemars::{self, JsonSchema},
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::{
    ServerState, ToolFailure, ToolSuccess,
    catalog::ToolId,
    tools::{AdapterError, AdapterResult, CallContext, ToolAdapter},
};

struct PlansAdapter;
static ADAPTER: PlansAdapter = PlansAdapter;
pub(crate) fn adapter() -> &'static dyn ToolAdapter {
    &ADAPTER
}

impl ToolAdapter for PlansAdapter {
    fn definitions(&self) -> Vec<Tool> {
        [
            ("plan_apply", "Apply a stored plan after a person confirms in the client. Arguments cannot confirm a change. A client without form elicitation cannot apply."),
            ("plan_discard", "Close an open plan in this server process."),
            ("plan_get", "Read a stored plan and its outcome in this server process."),
            ("plan_list", "List open and recent plans in this server process."),
        ].into_iter().map(|(name, description)| {
            let input = if name == "plan_list" { json!({"type":"object","properties":{},"additionalProperties":false}) }
                else { json!({"type":"object","properties":{"plan_id":{"type":"string"}},"required":["plan_id"],"additionalProperties":false}) };
            definition(name, description, input, name == "plan_list")
        }).collect()
    }
    fn call<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        self.call_with_context(tool, arguments, state, cancellation, CallContext::default())
    }
    fn call_with_context<'a>(
        &'a self,
        tool: ToolId,
        arguments: Option<&'a JsonObject>,
        state: &'a ServerState,
        _cancellation: CancellationToken,
        context: CallContext,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async move {
            if tool == ToolId::PlanApply {
                return Err(unsupported());
            }
            let args = arguments.cloned().unwrap_or_default();
            let id = if tool == ToolId::PlanList {
                if !args.is_empty() {
                    return Err(AdapterError::InvalidArgument);
                }
                None
            } else {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    plan_id: String,
                }
                let input: Input = serde_json::from_value(Value::Object(args))
                    .map_err(|_| AdapterError::InvalidArgument)?;
                crate::server::validate_text("plan_id", &input.plan_id, 1_024)
                    .map_err(|_| AdapterError::InvalidArgument)?;
                Some(input.plan_id)
            };
            let now = tokio::time::Instant::now();
            let mut store = state.plans.lock().expect("plan store lock");
            read(&mut store, &state.audit, tool, id, &context, now)
        })
    }
}

fn read<P: Clone>(
    store: &mut crate::plan::store::PlanStore<P>,
    sink: &crate::plan::audit::AuditSink,
    tool: ToolId,
    id: Option<String>,
    context: &CallContext,
    now: tokio::time::Instant,
) -> Result<AdapterResult, AdapterError> {
    use super::mutations::{drain_closed, local_error, output};
    use crate::plan::{audit, store::PlanState, view};
    let result = if let Some(id) = id {
        let before = store.get(&id, now).map(|p| p.state);
        drain_closed(sink, store, &context.protocol);
        let result = if tool == ToolId::PlanDiscard {
            store.discard(&id, now)
        } else {
            store.get(&id, now)
        };
        result.map(|p| {
            if tool == ToolId::PlanDiscard && before.as_ref().is_ok_and(|s| *s == PlanState::Open) {
                sink.emit(&audit::line(
                    audit::unix_seconds(),
                    p,
                    &context.protocol,
                    audit::Event::PlanClosed,
                ));
            }
            view::view(p, context.form_elicitation, false, now)
        })
    } else {
        Ok(view::list(&store.list(now), now))
    };
    drain_closed(sink, store, &context.protocol);
    result.map(output).map_err(local_error)
}

pub(super) fn unsupported() -> AdapterError {
    AdapterError::Core(Error::new(
        ErrorKind::Unsupported,
        "MCP mutation tools are not implemented.",
    ))
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum Output {
    Success(ToolSuccess<Value>),
    Failure(ToolFailure),
}

pub(super) fn definition(
    name: &'static str,
    description: &'static str,
    input: Value,
    list: bool,
) -> Tool {
    let mut schema = serde_json::to_value(schemars::schema_for!(Output)).expect("static schema");
    schema["type"] = json!("object");
    schema["$defs"]["ToolSuccess"]["properties"]["page"] = json!({"type":"null"});
    schema["$defs"]
        .as_object_mut()
        .expect("schema definitions")
        .remove("PageInfo");
    schema["$defs"]["ToolError"]["properties"]["http_status"]
        .as_object_mut()
        .expect("status schema")
        .remove("format");
    schema["$defs"]["ToolSuccess"]["properties"]["data"] = data_schema(list);
    let mut tool = Tool::new(
        name,
        description,
        input.as_object().expect("object schema").clone(),
    )
    .with_raw_output_schema(Arc::new(schema.as_object().expect("object schema").clone()))
    .with_annotations(
        ToolAnnotations::new()
            .read_only(!matches!(name, "plan_apply" | "plan_discard"))
            .destructive(name == "plan_apply")
            .idempotent(true)
            .open_world(matches!(name, "plan_apply" | "rules_set_enabled_plan")),
    );
    if name == "plan_apply" {
        tool = tool.with_meta(rmcp::model::MetaObject(
            json!({"anthropic/requiresUserInteraction":true})
                .as_object()
                .unwrap()
                .clone(),
        ));
    }
    tool
}

fn data_schema(list: bool) -> Value {
    if list { list_schema() } else { view_schema() }
}

fn view_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "plan": {
                "type": "object",
                "properties": {
                    "plan_id": {
                        "type": "string",
                        "pattern": "^pln_[0-9a-f]{32}$"
                    },
                    "kind": {
                        "type": "string"
                    },
                    "class": {
                        "type": "string"
                    },
                    "state": {
                        "type": "string",
                        "enum": [
                            "open",
                            "applying",
                            "applied",
                            "failed",
                            "unknown",
                            "declined",
                            "stale",
                            "expired",
                            "discarded"
                        ]
                    },
                    "action": {
                        "type": "string"
                    },
                    "expires_in_secs": {
                        "type": "integer",
                        "minimum": 0
                    },
                    "hash": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$"
                    },
                    "credential": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{12}$"
                    },
                    "details": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    },
                    "targets": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        }
                    },
                    "operation": {
                        "type": "object"
                    },
                    "confirmation": {
                        "type": "string",
                        "enum": [
                            "elicitation",
                            "unavailable"
                        ]
                    },
                    "cli_equivalent": {
                        "anyOf": [
                            {
                                "type": "array",
                                "items": {
                                    "type": "string"
                                }
                            },
                            {
                                "type": "null"
                            }
                        ]
                    }
                },
                "required": [
                    "plan_id",
                    "kind",
                    "class",
                    "state",
                    "action",
                    "expires_in_secs",
                    "hash",
                    "credential",
                    "details",
                    "targets",
                    "operation",
                    "confirmation",
                    "cli_equivalent"
                ],
                "additionalProperties": false
            },
            "outcome": {
                "anyOf": [
                    {
                        "type": "null"
                    },
                    {
                        "type": "object",
                        "properties": {
                            "requested": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "updated": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "unchanged": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "failed": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "complete": {
                                "type": "boolean"
                            },
                            "created": {
                                "type": [
                                    "object",
                                    "null"
                                ]
                            }
                        },
                        "required": [
                            "requested",
                            "updated",
                            "unchanged",
                            "failed",
                            "complete",
                            "created"
                        ],
                        "additionalProperties": false
                    }
                ]
            },
            "replayed": {
                "type": "boolean"
            }
        },
        "required": [
            "plan",
            "outcome",
            "replayed"
        ],
        "additionalProperties": false
    })
}

fn list_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "plans": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "plan_id": {
                            "type": "string",
                            "pattern": "^pln_[0-9a-f]{32}$"
                        },
                        "kind": {
                            "type": "string"
                        },
                        "class": {
                            "type": "string"
                        },
                        "state": {
                            "type": "string",
                            "enum": [
                                "open",
                                "applying",
                                "applied",
                                "failed",
                                "unknown",
                                "declined",
                                "stale",
                                "expired",
                                "discarded"
                            ]
                        },
                        "action": {
                            "type": "string"
                        },
                        "expires_in_secs": {
                            "type": "integer",
                            "minimum": 0
                        }
                    },
                    "required": [
                        "plan_id",
                        "kind",
                        "class",
                        "state",
                        "action",
                        "expires_in_secs"
                    ],
                    "additionalProperties": false
                }
            }
        },
        "required": [
            "plans"
        ],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{
        audit::AuditSink,
        store::{PlanState, PlanStore, tests::sample},
    };
    use tokio::time::{Duration, Instant};

    #[tokio::test(start_paused = true)]
    async fn expiry_and_discard_audit_use_a_collecting_sink() {
        let now = Instant::now();
        let mut store = PlanStore::default();
        let plan = sample(now);
        let id = plan.id.clone();
        store.insert(plan, now).unwrap();
        let (sink, lines) = AuditSink::collecting();
        let context = CallContext {
            form_elicitation: true,
            protocol: "2026-07-28".into(),
        };
        tokio::time::advance(Duration::from_secs(900)).await;
        let now = Instant::now();
        for tool in [ToolId::PlanGet, ToolId::PlanDiscard] {
            let result = read(&mut store, &sink, tool, Some(id.clone()), &context, now).unwrap();
            assert_eq!(result.data["plan"]["state"], "expired");
            assert_eq!(result.data["plan"]["expires_in_secs"], 0);
            assert_eq!(result.data["plan"]["confirmation"], "elicitation");
        }
        assert_eq!(lines.lock().unwrap().len(), 1);
        let line: Value = serde_json::from_str(&lines.lock().unwrap()[0]).unwrap();
        assert_eq!(line["audit"]["event"], "plan_closed");
        assert_eq!(line["audit"]["state"], "expired");
        let plan = sample(now);
        let id = plan.id.clone();
        store.insert(plan, now).unwrap();
        for _ in 0..2 {
            read(
                &mut store,
                &sink,
                ToolId::PlanDiscard,
                Some(id.clone()),
                &context,
                now,
            )
            .unwrap();
        }
        assert_eq!(lines.lock().unwrap().len(), 2);
        let plan = sample(now);
        let id = plan.id.clone();
        store.insert(plan, now).unwrap();
        store.begin_apply(&id, now).unwrap();
        let error = read(
            &mut store,
            &sink,
            ToolId::PlanDiscard,
            Some(id.clone()),
            &context,
            now,
        )
        .unwrap_err();
        let AdapterError::Tool(error) = error else {
            panic!("expected local error")
        };
        assert_eq!(error.code, "plan_not_open");
        assert_eq!(store.get(&id, now).unwrap().state, PlanState::Applying);
        assert_eq!(lines.lock().unwrap().len(), 2);
    }
}
