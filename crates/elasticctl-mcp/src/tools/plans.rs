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
    tools::{AdapterError, AdapterResult, ToolAdapter},
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
        _tool: ToolId,
        _arguments: Option<&'a JsonObject>,
        _state: &'a ServerState,
        _cancellation: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<AdapterResult, AdapterError>> + Send + 'a>> {
        Box::pin(async { Err(unsupported()) })
    }
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
