[Back to elasticctl-mcp-mutation-design](../elasticctl-mcp-mutation-design.md)

## 2. Consent model

Three parties act on one server process:

| Party | Controls | Trusted for |
| --- | --- | --- |
| Operator | The command line, the profile, the credential, and the choice of client | Which classes of change are possible at all |
| Person at the client | The client's dialogs | Agreeing to one plan |
| Model | Tool names and tool arguments | Nothing. Its input is a request, never a decision |

Consent is a person at the client accepting a description of one stored plan
that the server wrote, on a channel that tool arguments cannot write to.

The CLI guard asks "did the caller pass `--yes`". Over MCP the caller is the
model, so that question has no safe answer. 0.9 asks a different party.

The design rests on four rules. Each has one reason.

| Rule | Decision | Reason |
| --- | --- | --- |
| C1 | Mutation classes are enabled only by `mcp serve --allow-mutations <classes>`. The default is none. | The operator, not the session, decides what can change. |
| C2 | A mutation is two calls: a planner that only reads, then `plan_apply` with a plan id. | The thing confirmed is a stored object the server controls, not text the model can restate. |
| C3 | `plan_apply` applies only after a form elicitation answered `accept` with `apply: true`. | Elicitation answers come from the client, outside `arguments`. |
| C4 | No form elicitation, no apply. | Failing closed is the only safe default when no person can be asked. |

Client tool approval is not consent. Clients can allow a tool once and
forever, or skip prompts in a mode. The server cannot see which happened. 0.9
still sets what makes clients prompt, as defense in depth:

- `plan_apply` has `readOnlyHint: false` and `destructiveHint: true`.
  Codex CLI prompts for a destructive tool in its default approval mode.
- `plan_apply` has `_meta["anthropic/requiresUserInteraction"]: true`. Claude
  Code then prompts on every call in every permission mode, ignores allow
  rules and hook approvals, and denies the call in non-interactive runs.
- Planners have `readOnlyHint: true`. They send no write.

In Claude Code a person therefore answers twice for one apply: the permission
card for the `plan_apply` call, then the form. The card proves a person is
present. The form shows what changes. Both are kept; the owner accepted the
two prompts on 2026-11-10.

What the server never accepts as consent:

- any tool argument. `plan_apply` has one input, `plan_id`, and rejects
  unknown fields. There is no `confirm`, `yes`, `force`, or `hash` input;
- a planner call. A plan is open, not approved;
- an elicitation answer of `accept` without `apply: true`. A client that
  accepts with defaults sends `apply: false`;
- an answer whose `requestState` does not match the handle the server issued
  for that plan, or that arrives twice;
- anything in tool results, resources, or prompts, including text that says a
  person agreed.

### 2.1 What happens without elicitation

"Without elicitation" means the request's client capabilities have no
`elicitation` entry, or have one that names `url` only. On protocol
`2026-07-28` they are the capabilities carried in that request's metadata;
on the legacy path they are the ones the client sent with `initialize`.

1. Planners work. They are reads. The plan result carries
   `confirmation: "unavailable"` so the model knows before it tries.
2. `plan_apply` returns the tool error `confirmation_unavailable`, kind
   `unsupported`. It sends no Elastic request at all, not even the re-check.
3. The plan stays open until it expires. `plan_get` still returns it.
4. The plan carries `cli_equivalent`: the argument list of the CLI command
   that makes the same change, without `--yes` and without global flags.
   A person runs it in a terminal, reads the dry run, and adds `--yes`.
   `rules_create` has no CLI equivalent that takes inline content; its value
   is `null` and the person uses `rules import` with a file.
5. No flag, environment variable, or tool makes the server apply in this
   state. There is no "trusted client" list.

The same holds when a client declares elicitation but cannot reach a person:
the client answers `decline` or `cancel`, and the plan is not applied.

### 2.2 Rejected alternatives

| Alternative | Why not |
| --- | --- |
| A `confirm: true` or `--yes`-like argument | The model writes arguments. This is the failure the guard exists to prevent. |
| Echoing a code from the plan result back to `plan_apply` | The model reads tool results. A code it can read is a code it can echo. |
| Client tool approval alone | It is a SHOULD in the protocol, can be granted once and forever, and is skipped in some client modes. |
| Startup flag alone, then direct apply | It turns one operator decision into consent for every later change in the session. |
| A second CLI command the person runs to approve a plan (`mcp confirm <plan_id>`) | It needs a local channel into the server process. A model with a shell tool runs under the same OS user and could run it too, so it adds a channel without adding a party. The existing CLI already gives that person a guarded path. |
| URL mode elicitation with a local confirmation page | It needs an HTTP listener, which 0.7 excluded. A caller with a shell can fetch the URL. It also asks the person to trust a localhost link. |
| An empty confirmation form (accept or decline only) | Codex CLI accepts a form without fields on its own when approvals are off and access is full. A required field is declined there instead. |
| A typed confirmation code in the form | It adds friction for changes whose direct effect a second call sets back or that only add. A client hook that can accept can also copy a code. Kept in reserve for a destructive class, which 0.9 does not have. |
| The MCP tasks extension for approval gates | The client matrix lists no client support, and every 0.9 apply is one request. |

### 2.3 Limits of the model

The server can check that an answer came through the elicitation channel. It
cannot check that a person produced it. These limits are stated to operators
in the README and are not defects:

- **A client can answer for the person.** Claude Code runs `Elicitation` hooks
  that can return `accept` with content. A hook is operator configuration.
  When it accepts, the operator's configuration is the consenting party. In
  Claude Code the permission card on `plan_apply` still needs a person.
- **A model with a shell does not need MCP.** Coding clients give the model a
  shell under the operator's OS user. It can run `elkctl ... --yes` with the
  same profile. The client's command approval is the control there. 0.9 does
  not make this worse and cannot make it better.
- **The form shows text from the stack.** Rule names and case titles appear in
  the consent text as quoted data. They cannot change the static lines, the
  target line, or the count of affected objects
  ([section 6.1](06-confirmation-protocol.md#61-consent-text)).
- **A person can be asked often.** A model can plan and ask again after a
  decline. A declined plan is closed, each plan prompts at most three times,
  and at most eight plans are open. That bounds the rate. It does not stop
  it.
- **The last check is not atomic.** The stack offers no conditional write for
  rule toggles or alert status. A change in the instant between the last
  re-read and the write is not seen
  ([section 5.3](05-plans.md#53-drift)).
