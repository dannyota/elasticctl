use super::common::*;
pub const BOUNDED_POLICY_CAP: u64 = 1_000;
pub async fn list_first_page(t: &Transport) -> Result<Option<Vec<IntegrationPolicySummary>>> {
    let page = integration_policies::list_page(t, 1).await?;
    bounded_page(page)
}

fn bounded_page(
    page: integration_policies::IntegrationPolicyPage,
) -> Result<Option<Vec<IntegrationPolicySummary>>> {
    if page.page != 1
        || page.per_page != BOUNDED_POLICY_CAP
        || page.items.len() as u64 > BOUNDED_POLICY_CAP
        || page.items.len() as u64 > page.total
    {
        return Err(http("invalid bounded policy page metadata"));
    }
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    for item in page.items {
        let row = summary_from_item(&item)?;
        if !ids.insert(row.id.clone()) {
            return Err(http("duplicate bounded policy id"));
        }
        rows.push(row);
    }
    if page.total > rows.len() as u64 {
        return Ok(None);
    }
    Ok(Some(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn page(count: usize, total: u64) -> integration_policies::IntegrationPolicyPage {
        let fixture: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/traditional-9.5.1/integration_policies_list.json"
        )))
        .unwrap();
        let row = fixture["response"]["items"][0].as_object().unwrap();
        integration_policies::IntegrationPolicyPage {
            items: (0..count)
                .map(|i| {
                    let mut r = row.clone();
                    r.insert("id".into(), Value::String(i.to_string()));
                    r
                })
                .collect(),
            total,
            page: 1,
            per_page: 1000,
        }
    }
    #[test]
    fn bounded_page_caps_and_metadata() {
        assert_eq!(bounded_page(page(3, 3)).unwrap().unwrap().len(), 3);
        assert!(bounded_page(page(1000, 1001)).unwrap().is_none());
        let mut duplicate = page(3, 3);
        duplicate.items[1] = duplicate.items[0].clone();
        assert_eq!(bounded_page(duplicate).unwrap_err().kind, ErrorKind::Http);
        let mut wrong = page(3, 3);
        wrong.page = 2;
        assert_eq!(bounded_page(wrong).unwrap_err().kind, ErrorKind::Http);
        let mut wrong = page(3, 3);
        wrong.per_page = 999;
        assert_eq!(bounded_page(wrong).unwrap_err().kind, ErrorKind::Http);
        assert_eq!(bounded_page(page(3, 2)).unwrap_err().kind, ErrorKind::Http);
        assert_eq!(
            bounded_page(page(1001, 1001)).unwrap_err().kind,
            ErrorKind::Http
        );
    }
}
