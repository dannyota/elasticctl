[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 8. Package dependencies

Planning groups integration artifacts by package name and rejects a file that
asks for more than one version of the same package.

- The exact installed version is ready.
- No installed version is a planned package installation.
- A different installed version is `conflict`.
- A missing or incompatible registry version fails before a policy write when
  Fleet exposes that result during preflight, or as the decoded create error.

Kibana's package-policy create service calls its exact-version package install
path before compiling and saving the policy. elasticctl does not add a public
`packages install` command or issue a redundant install request. Preview names
`package@version` as an implicit side effect. Apply lets guarded policy create
perform the installation, then verifies the installed version and stored
policy.

If create fails after an installation attempt, elasticctl reports the result
and re-reads package state. When the exact requested version became installed,
it advances the shared package snapshot, reports that observed install once,
and permits later rows using it. A different version or malformed read blocks
only rows using that package. It never uninstalls as rollback. Successful
policy deletion also leaves the package installed.

