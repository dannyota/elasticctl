#[path = "mcp_compose/calls.rs"]
mod calls;
#[path = "mcp_compose/expect.rs"]
mod expect;
#[path = "mcp_compose/fill.rs"]
pub(super) mod fill;
#[path = "mcp_compose/objects.rs"]
mod objects;
#[path = "mcp_compose/resources.rs"]
mod resources;
#[path = "mcp_compose/shape.rs"]
mod shape;

use std::path::Path;

use elasticctl_core::{Profile, Transport};

use crate::fleet::fixture::FleetFixtureLease;
use crate::{LiveCleanup, TestResult, read_validated_default_data_view};
use calls::Timings;
use expect::Expected;
use fill::{LiveFillRemote, RuleFill};
use objects::{ComposeIds, Provisioned};

trait ComposeStack {
    fn read_default(&mut self) -> TestResult<Option<String>>;
    fn provision(&mut self, ids: &ComposeIds, cleanup: &mut LiveCleanup)
    -> TestResult<Provisioned>;
    fn prepare_fleet(&mut self) -> TestResult;
    fn fill(&mut self, ids: &ComposeIds, cleanup: &mut LiveCleanup)
    -> TestResult<Option<RuleFill>>;
    fn calls(
        &mut self,
        ids: &ComposeIds,
        provisioned: &Provisioned,
        fill: Option<&RuleFill>,
    ) -> TestResult;
    fn unfill(&mut self, fill: &RuleFill, cleanup: &mut LiveCleanup) -> TestResult;
}

fn run_compose(
    stack: &mut impl ComposeStack,
    cleanup: &mut LiveCleanup,
    ids: &ComposeIds,
) -> TestResult {
    let original_default = stack.read_default()?;
    objects::register_compose(cleanup, ids, original_default);
    let provisioned = stack.provision(ids, cleanup)?;
    stack.prepare_fleet()?;
    let fill = stack.fill(ids, cleanup)?;
    let calls = stack.calls(ids, &provisioned, fill.as_ref());
    let unfill = fill
        .as_ref()
        .map_or(Ok(()), |fill| stack.unfill(fill, cleanup));
    match (calls, unfill) {
        (Err(calls), Err(unfill)) => Err(format!("{calls}; {unfill}")),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

pub(super) fn run_contract(
    config: &Path,
    scratch: &Path,
    cleanup: &mut LiveCleanup,
    lease: &mut FleetFixtureLease,
) -> TestResult {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|_| "MCP compose runtime could not be started.".to_string())?;
    let transport = Transport::new(&cleanup.profile)
        .map_err(|_| "MCP compose transport could not be created.".to_string())?;
    let mut stack = LiveStack {
        config,
        scratch,
        profile: cleanup.profile.clone(),
        lease,
        runtime: &runtime,
        transport: &transport,
    };
    run_compose(&mut stack, cleanup, &ComposeIds::new())
}

struct LiveStack<'a> {
    config: &'a Path,
    scratch: &'a Path,
    profile: Profile,
    lease: &'a mut FleetFixtureLease,
    runtime: &'a tokio::runtime::Runtime,
    transport: &'a Transport,
}

impl LiveStack<'_> {
    fn fill_remote(&self) -> LiveFillRemote<'_> {
        LiveFillRemote {
            runtime: self.runtime,
            transport: self.transport,
            import: Some((self.config, self.scratch)),
            chunks: 0,
        }
    }
}

impl ComposeStack for LiveStack<'_> {
    fn read_default(&mut self) -> TestResult<Option<String>> {
        read_validated_default_data_view(&self.profile)
    }

    fn provision(
        &mut self,
        ids: &ComposeIds,
        cleanup: &mut LiveCleanup,
    ) -> TestResult<Provisioned> {
        objects::provision_live(
            self.config,
            self.scratch,
            self.runtime,
            self.transport,
            ids,
            cleanup,
        )
    }

    fn prepare_fleet(&mut self) -> TestResult {
        self.runtime
            .block_on(self.lease.prepare())
            .map_err(|_| "MCP compose Fleet fixture could not be prepared.".to_string())
    }

    fn fill(
        &mut self,
        ids: &ComposeIds,
        cleanup: &mut LiveCleanup,
    ) -> TestResult<Option<RuleFill>> {
        fill::fill_corpus(
            &mut self.fill_remote(),
            cleanup,
            &ids.index,
            &ids.fill_nonce,
        )
    }

    fn calls(
        &mut self,
        ids: &ComposeIds,
        provisioned: &Provisioned,
        fill: Option<&RuleFill>,
    ) -> TestResult {
        let expected = Expected {
            ids,
            provisioned,
            fill,
        };
        let mut timings = Timings::default();
        let result = calls::run_calls(self.config, &expected, &mut timings);
        let logged = calls::write_private_lines(
            &calls::private_timing_path(provisioned.flavor),
            &timings.private_lines(),
        );
        calls::emit_public_lines(&timings.public_lines());
        result.and(logged)
    }

    fn unfill(&mut self, fill: &RuleFill, cleanup: &mut LiveCleanup) -> TestResult {
        fill::unfill_corpus(&mut self.fill_remote(), cleanup, fill)
    }
}

#[cfg(test)]
mod tests {
    use super::fill::tests::FakeFill;
    use super::fill::{FillRemote, delete_fill, fill_corpus, unfill_corpus};
    use super::*;
    use crate::{McpOutcomeFailure, McpRunSteps, run_mcp_steps};
    use elasticctl_core::Flavor;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct FakeStack {
        events: Rc<RefCell<Vec<&'static str>>>,
        failure: &'static str,
        remote: FakeFill,
        unregistered_at_provision: Option<Vec<String>>,
    }

    impl FakeStack {
        fn new(events: Rc<RefCell<Vec<&'static str>>>, failure: &'static str) -> Self {
            Self {
                events,
                failure,
                remote: FakeFill::new(Flavor::SelfManaged, 3_000),
                unregistered_at_provision: None,
            }
        }

        fn step(&self, event: &'static str) -> TestResult {
            self.events.borrow_mut().push(event);
            if self.failure == event {
                Err(event.to_string())
            } else {
                Ok(())
            }
        }
    }

    impl ComposeStack for FakeStack {
        fn read_default(&mut self) -> TestResult<Option<String>> {
            self.step("read-default").map(|()| None)
        }

        fn provision(
            &mut self,
            ids: &ComposeIds,
            cleanup: &mut LiveCleanup,
        ) -> TestResult<Provisioned> {
            self.unregistered_at_provision = Some(objects::unregistered(ids, cleanup));
            self.step("provision")?;
            Ok(Provisioned {
                flavor: Flavor::SelfManaged,
                work_alert: "work".to_string(),
                degraded_alert: "degraded".to_string(),
                cases: Vec::new(),
                prebuilt_total: 0,
            })
        }

        fn prepare_fleet(&mut self) -> TestResult {
            self.step("fleet")
        }

        fn fill(
            &mut self,
            ids: &ComposeIds,
            cleanup: &mut LiveCleanup,
        ) -> TestResult<Option<RuleFill>> {
            self.step("fill")?;
            fill_corpus(&mut self.remote, cleanup, &ids.index, &ids.fill_nonce)
        }

        fn calls(&mut self, _: &ComposeIds, _: &Provisioned, _: Option<&RuleFill>) -> TestResult {
            self.step("calls")
        }

        fn unfill(&mut self, fill: &RuleFill, cleanup: &mut LiveCleanup) -> TestResult {
            self.step("unfill")?;
            unfill_corpus(&mut self.remote, cleanup, fill)
        }
    }

    struct ComposeRunSteps {
        stack: FakeStack,
        cleanup: LiveCleanup,
        ids: ComposeIds,
        fail_delete: bool,
    }

    impl ComposeRunSteps {
        fn new(failure: &'static str, fail_delete: bool) -> Self {
            let mut cleanup = LiveCleanup::for_test();
            cleanup.finished = true;
            Self {
                stack: FakeStack::new(Rc::new(RefCell::new(Vec::new())), failure),
                cleanup,
                ids: ComposeIds::new(),
                fail_delete,
            }
        }

        fn events(&self) -> Vec<&'static str> {
            self.stack.events.borrow().clone()
        }
    }

    impl McpRunSteps for ComposeRunSteps {
        fn run_contract(&mut self) -> TestResult {
            run_compose(&mut self.stack, &mut self.cleanup, &self.ids)
        }

        fn finish_fleet(&mut self) -> TestResult {
            self.stack.events.borrow_mut().push("finish-fleet");
            Ok(())
        }

        fn finish_general(&mut self) -> TestResult {
            self.stack.events.borrow_mut().push("finish-general");
            if self.fail_delete {
                self.stack.remote.delete_failures = usize::MAX;
            }
            let remote = &mut self.stack.remote;
            let failures = self
                .cleanup
                .clean_rule_fills(|prefix, count| delete_fill(remote, prefix, count));
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            }
        }

        fn audit_baseline(&mut self) -> TestResult {
            self.stack.events.borrow_mut().push("audit-baseline");
            if self.stack.remote.created.is_empty() {
                Ok(())
            } else {
                Err("fill residue".to_string())
            }
        }
    }

    const FINISH: [&str; 3] = ["finish-fleet", "finish-general", "audit-baseline"];

    #[test]
    fn a_clean_run_removes_the_fill_after_the_calls() {
        let mut steps = ComposeRunSteps::new("", false);
        assert_eq!(run_mcp_steps(&mut steps), Ok(()));
        let mut expected = vec![
            "read-default",
            "provision",
            "fleet",
            "fill",
            "calls",
            "unfill",
        ];
        expected.extend(FINISH);
        assert_eq!(steps.events(), expected);
        assert_eq!(steps.stack.unregistered_at_provision, Some(Vec::new()));
        assert!(steps.cleanup.rule_fills.is_empty());
        assert!(steps.stack.remote.created.is_empty());
    }

    #[test]
    fn provisioning_failure_after_registration_cleans_up() {
        let mut steps = ComposeRunSteps::new("provision", false);
        assert_eq!(
            run_mcp_steps(&mut steps),
            Err(McpOutcomeFailure::Contract("provision".to_string()))
        );
        let mut expected = vec!["read-default", "provision"];
        expected.extend(FINISH);
        assert_eq!(steps.events(), expected);
        assert_eq!(
            steps.stack.unregistered_at_provision,
            Some(Vec::new()),
            "every object was registered before the first write"
        );
        assert!(objects::unregistered(&steps.ids, &steps.cleanup).is_empty());
    }

    #[test]
    fn a_protocol_failure_still_removes_the_fill() {
        let mut steps = ComposeRunSteps::new("calls", false);
        assert_eq!(
            run_mcp_steps(&mut steps),
            Err(McpOutcomeFailure::Contract("calls".to_string()))
        );
        let mut expected = vec![
            "read-default",
            "provision",
            "fleet",
            "fill",
            "calls",
            "unfill",
        ];
        expected.extend(FINISH);
        assert_eq!(steps.events(), expected);
        assert!(steps.stack.remote.created.is_empty());
        assert!(steps.cleanup.rule_fills.is_empty());
    }

    #[test]
    fn a_failed_contract_delete_leaves_the_fill_to_cleanup() {
        let mut steps = ComposeRunSteps::new("unfill", false);
        assert_eq!(
            run_mcp_steps(&mut steps),
            Err(McpOutcomeFailure::Contract("unfill".to_string()))
        );
        assert!(
            steps.stack.remote.created.is_empty(),
            "the registered fill was deleted by cleanup"
        );
    }

    #[test]
    fn cleanup_failure_takes_precedence_over_a_contract_failure() {
        let mut steps = ComposeRunSteps::new("unfill", true);
        assert_eq!(
            run_mcp_steps(&mut steps),
            Err(McpOutcomeFailure::Cleanup(
                "general cleanup failed".to_string()
            ))
        );
        assert_eq!(steps.stack.remote.created.len(), 1_000);
        assert_eq!(steps.stack.remote.delete_attempts, 3);
    }

    #[test]
    fn the_fill_stage_never_writes_for_cloud_flavors() {
        for flavor in [Flavor::Serverless, Flavor::ElasticCloudHosted] {
            let mut steps = ComposeRunSteps::new("", false);
            steps.stack.remote = FakeFill::new(flavor, 2_263);
            assert_eq!(run_mcp_steps(&mut steps), Ok(()));
            let mut expected = vec!["read-default", "provision", "fleet", "fill", "calls"];
            expected.extend(FINISH);
            assert_eq!(steps.events(), expected);
            assert!(steps.stack.remote.imported.is_empty());
            assert!(steps.cleanup.rule_fills.is_empty());
            assert_eq!(steps.stack.remote.flavor().unwrap(), flavor);
        }
    }
}

#[cfg(test)]
#[path = "mcp_compose/recorded.rs"]
mod recorded;
