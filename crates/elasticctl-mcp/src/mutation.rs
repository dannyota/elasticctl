use std::collections::BTreeSet;

use elasticctl_core::{Error, ErrorKind, Result};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MutationClass {
    AlertsTriage,
    Cases,
    RulesCreate,
    RulesToggle,
}

impl MutationClass {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AlertsTriage => "alerts-triage",
            Self::Cases => "cases",
            Self::RulesCreate => "rules-create",
            Self::RulesToggle => "rules-toggle",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MutationClasses(BTreeSet<MutationClass>);

impl MutationClasses {
    pub fn parse<I, S>(values: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut classes = BTreeSet::new();
        for value in values {
            for piece in value.as_ref().split(',') {
                match piece {
                    "alerts-triage" => {
                        classes.insert(MutationClass::AlertsTriage);
                    }
                    "cases" => {
                        classes.insert(MutationClass::Cases);
                    }
                    "rules-create" => {
                        classes.insert(MutationClass::RulesCreate);
                    }
                    "rules-toggle" => {
                        classes.insert(MutationClass::RulesToggle);
                    }
                    _ => return Err(Error::new(ErrorKind::Error, "Invalid MCP serve arguments.")),
                }
            }
        }
        Ok(Self(classes))
    }

    pub fn contains(&self, class: MutationClass) -> bool {
        self.0.contains(&class)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn names(&self) -> Vec<&'static str> {
        self.0.iter().map(|class| class.name()).collect()
    }
}
