use std::collections::BTreeSet;

use elasticctl_core::{Error, ErrorKind, Result};

/// An explicitly enabled mutation class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MutationClass {
    RulesToggle,
}

impl MutationClass {
    pub const fn name(self) -> &'static str {
        match self {
            Self::RulesToggle => "rules-toggle",
        }
    }
}

/// The mutation classes enabled for one server session.
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
