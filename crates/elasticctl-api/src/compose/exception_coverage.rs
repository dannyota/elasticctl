use crate::{
    Rule, exceptions,
    model::{ListKey, exception_refs},
};
use elasticctl_core::{Error, Result, Transport};
#[derive(Debug)]
pub struct ListFacts {
    pub name: Option<String>,
    pub list_type: Option<String>,
    pub item_count: u64,
}
#[derive(Debug)]
pub struct ListCoverage {
    pub key: ListKey,
    pub ref_type: String,
    pub facts: std::result::Result<ListFacts, Error>,
}
#[derive(Debug)]
pub struct ExceptionCoverage {
    pub referenced: usize,
    pub truncated: bool,
    pub lists: Vec<ListCoverage>,
}
pub async fn exception_coverage(t: &Transport, rule: &Rule) -> Result<ExceptionCoverage> {
    let refs = exception_refs(rule);
    let referenced = refs.len();
    let mut lists = Vec::new();
    for r in refs.into_iter().take(super::MAX_EXCEPTION_LISTS) {
        let key = ListKey {
            list_id: r.list_id,
            namespace_type: r.namespace_type,
        };
        let facts: Result<ListFacts> = async {
            let list = exceptions::get_list(t, &key).await?;
            let item_count = exceptions::count_items(t, &key).await?;
            let field = |k| -> Result<Option<String>> {
                list.as_map()
                    .get(k)
                    .map(|v| {
                        v.as_str().map(str::to_owned).ok_or_else(|| {
                            Error::new(
                                elasticctl_core::ErrorKind::Http,
                                "invalid exception list field",
                            )
                        })
                    })
                    .transpose()
            };
            Ok(ListFacts {
                name: field("name")?,
                list_type: field("type")?,
                item_count,
            })
        }
        .await;
        if let Err(e) = &facts
            && super::is_fatal(e.kind)
        {
            return Err(facts.unwrap_err());
        }
        lists.push(ListCoverage {
            key,
            ref_type: r.ref_type,
            facts,
        });
    }
    Ok(ExceptionCoverage {
        referenced,
        truncated: referenced > super::MAX_EXCEPTION_LISTS,
        lists,
    })
}
