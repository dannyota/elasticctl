[Back to elasticctl-fleet-design](../elasticctl-fleet-design.md)

## 7. Secrets and environment references

Fleet stores integration secret values separately. A later read exposes a
reference or hidden placeholder, not the original value. Export fails closed
if the policy has secret references. Its error names sorted policy and field
paths but never prints reference ids or values.

A deployment without secret storage keeps a secret variable in plaintext and
returns it on read, so references alone cannot prove absence. Export and
import planning both read `GET /api/fleet/epm/packages/{name}/{version}` for
the exact package version and reject every supplied package, input, or stream
variable the package declares secret. If that read fails, the classified
transport error stands. If the metadata cannot prove whether a configured
variable is secret, the operation fails `unsupported` before the guard.
Offline `validate` checks document structure only. Secret injection from an
environment, file, or secret store is a future capability.

The exact package response defines package variables in optional `item.vars`
and input variables in optional
`item.policy_templates[].inputs[].vars`. It defines stream variables in
`item.data_streams[].streams[].vars`, not only in an input's legacy nested
`streams`. Every variable definition has a non-empty unique `name`; absent
`secret` means false, while a present non-boolean value is malformed `http`.

Input schema keys are `<template-name>-<input-type>`. Template names and
composite input keys are unique. A template's absent `data_streams` selects all
top-level data streams, an empty list selects none, and each non-empty selector
must resolve exactly once as either an exact dataset or
`<package-name>.<selector>`. Each top-level data stream has one unique,
non-empty full dataset. Each of its stream entries has one non-empty `input`.
Joining a stream to template inputs with the same type and a matching dataset
must yield exactly one composite input key. Zero or multiple candidates,
duplicate selectors, datasets, stream inputs, or resulting stream keys are
malformed `http`.

For compatibility, legacy `policy_templates[].inputs[].streams` definitions
remain accepted. When modern and legacy metadata define the same composite
input and dataset, their normalized variable definitions must be identical;
otherwise metadata is malformed. A configured package variable, input key,
stream dataset, or variable without a matching definition remains
`unsupported` and error text never includes its value.

Output, download-source, Fleet Server host, cloud-connector, and extra-space
ids name target-local infrastructure. 0.6 neither exports nor remaps them. A
policy using one is unsupported rather than silently changed to a default.

