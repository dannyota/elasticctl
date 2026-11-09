[Back to elasticctl-triage-design](../elasticctl-triage-design.md)

## 2. Triage is operational, not as-code

The rules and exceptions verticals are as-code: the mirror on disk is the
source of truth and `state push` reconciles the server toward it. Triage must
not get that treatment, and the reason is directional. A rule mirror describes
*intent* — what should be deployed. An alert is an *event record*: it appears
because data matched a rule, and its lifecycle (open, acknowledged, closed) is
a workflow position, not configuration. Reconciling a directory of alerts
against a server would mean either resurrecting closed alerts or mass-closing
live ones every time the mirror went stale — both are triage decisions being
made by a file's absence, exactly the failure `state push` refuses for rules.

Cases sit in the same category: they are collaboration records with authors,
comments, and timestamps. A case pulled to disk is an export, not a mirror.

Consequences:

- No `state` integration. `state pull|diff|push` never touch alerts or cases.
- No `--overwrite`-style reconciliation verbs. Every mutation names an
  explicit id list or an explicit query.
- `alerts list --out` and `cases list --out` are exports for reporting, with
  no import counterpart.

