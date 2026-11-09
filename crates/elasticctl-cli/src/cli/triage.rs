use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum SearchAction {
    /// Run an ES|QL query
    Esql {
        /// The ES|QL query text
        query: String,
        /// Resolve a Kibana data view to an index pattern
        #[arg(long, conflicts_with = "index")]
        data_view: Option<String>,
        /// Explicit index or alias, overrides the query's own source
        #[arg(long, conflicts_with = "data_view")]
        index: Option<String>,
        /// Cap the number of result rows
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Run a Query DSL search body
    Dsl {
        /// JSON body or @path
        body: String,
        /// Resolve a Kibana data view to an index pattern
        #[arg(long, conflicts_with = "index")]
        data_view: Option<String>,
        /// Explicit index or alias
        #[arg(long, conflicts_with = "data_view")]
        index: Option<String>,
        /// Cap the number of result rows
        #[arg(long)]
        limit: Option<usize>,
        /// Add `_id`, `_index`, and `_score` to each rendered row
        #[arg(long)]
        with_meta: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AlertsAction {
    /// List detection alerts
    List {
        /// Filter by workflow status
        #[arg(long, value_parser = ["open", "acknowledged", "closed"])]
        status: Option<String>,
        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,
        /// Filter by rule name or rule_id
        #[arg(long)]
        rule: Option<String>,
        /// Filter by workflow tag
        #[arg(long)]
        tag: Option<String>,
        /// Filter by assignee username, or uid:<profile_uid>
        #[arg(long)]
        assignee: Option<String>,
        /// Only alerts newer than a duration (90m, 24h, 7d) or an ISO timestamp
        #[arg(long)]
        since: Option<String>,
        /// Substring match on the rule name and reason text
        #[arg(long)]
        search: Option<String>,
        /// Cap the rows returned (peek default: 100; --out is uncapped)
        #[arg(long)]
        limit: Option<usize>,
        /// Merge _id into each alert document
        #[arg(long)]
        with_meta: bool,
    },
    /// Show one alert by document id
    Get {
        /// The alert document _id
        alert_id: String,
    },
    /// Acknowledge alerts, by id or by query
    Ack {
        /// Alert document ids
        #[arg(conflicts_with = "query", required_unless_present = "query")]
        alert_ids: Vec<String>,
        /// Query DSL selecting the alerts: inline JSON or @file
        #[arg(long)]
        query: Option<String>,
    },
    /// Reopen alerts, by id or by query
    Open {
        /// Alert document ids
        #[arg(conflicts_with = "query", required_unless_present = "query")]
        alert_ids: Vec<String>,
        /// Query DSL selecting the alerts: inline JSON or @file
        #[arg(long)]
        query: Option<String>,
    },
    /// Close alerts, by id or by query
    Close {
        /// Alert document ids
        #[arg(conflicts_with = "query", required_unless_present = "query")]
        alert_ids: Vec<String>,
        /// Query DSL selecting the alerts: inline JSON or @file
        #[arg(long)]
        query: Option<String>,
        /// Close reason recorded on each alert
        #[arg(long)]
        reason: Option<String>,
        /// On a version conflict: abort (default) or proceed
        #[arg(long, value_parser = ["abort", "proceed"])]
        conflicts: Option<String>,
    },
    /// Add or remove workflow tags on alerts
    Tag {
        /// Alert document ids
        #[arg(required = true)]
        alert_ids: Vec<String>,
        /// Tag to add (repeatable)
        #[arg(long)]
        add: Vec<String>,
        /// Tag to remove (repeatable)
        #[arg(long)]
        remove: Vec<String>,
    },
    /// Assign or unassign users on alerts
    Assign {
        /// Alert document ids
        #[arg(required = true)]
        alert_ids: Vec<String>,
        /// Username or uid:<profile_uid> to assign (repeatable)
        #[arg(long)]
        add: Vec<String>,
        /// Username or uid:<profile_uid> to unassign (repeatable)
        #[arg(long)]
        remove: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CasesAction {
    /// List cases
    List {
        /// Filter by status
        #[arg(long, value_parser = ["open", "in-progress", "closed"])]
        status: Option<String>,
        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,
        /// Filter by tag
        #[arg(long)]
        tag: Option<String>,
        /// Substring match on title and description
        #[arg(long)]
        search: Option<String>,
        /// Cap the rows returned (peek default: 100; --out is uncapped)
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show one case in full
    Get {
        /// The case id
        case_id: String,
    },
    /// Create a case
    Create {
        /// The case title
        #[arg(long)]
        title: String,
        /// The case description (defaults to the title)
        #[arg(long)]
        description: Option<String>,
        /// Tag to set (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Case severity
        #[arg(long)]
        severity: Option<String>,
        /// Username or uid:<profile_uid> to assign (repeatable)
        #[arg(long)]
        assignee: Vec<String>,
    },
    /// Close cases
    Close {
        /// Case ids
        #[arg(required = true)]
        case_ids: Vec<String>,
    },
    /// Reopen cases
    Open {
        /// Case ids
        #[arg(required = true)]
        case_ids: Vec<String>,
    },
    /// Delete cases permanently
    Delete {
        /// Case ids
        #[arg(required = true)]
        case_ids: Vec<String>,
    },
    /// Attach alerts to a case
    Attach {
        /// The case id
        case_id: String,
        /// Alert document id to attach (repeatable)
        #[arg(long, required = true)]
        alert: Vec<String>,
    },
    /// Add a comment to a case
    Comment {
        /// The case id
        case_id: String,
        /// The comment text
        #[arg(long)]
        message: String,
    },
}
