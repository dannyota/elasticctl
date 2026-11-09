[Back to elasticctl-design](../elasticctl-design.md)

## 12. Credentials in this repository

Development credentials live in `.env`, which is gitignored and has mode `0600`.
`.env.example` is committed and contains placeholders only. The Elastic key in
use is a **project-scoped** serverless key: it authenticates API calls but
cannot create, list, or resize projects. Managing projects and deployments
needs an organization key with Cloud API access, created in the Cloud console
under Organization > API keys, against `api.elastic-cloud.com`.

All three key types carry the `essu_` prefix; the console offers no other. The
prefix therefore identifies nothing. Only `GET /_security/_authenticate`
reports the realm, which is the discriminator.

Provisioning a Hosted deployment through the Cloud API does not currently work
for this organization. `GET /deployments/templates` serves a catalogue whose
every entry `POST /deployments` rejects as `legacy_dt`. The result is the same
for two organization keys and for the documented `template_id` query parameter,
which has the server expand the template. No AWS region resolves for Hosted
templates. The console creates the same deployment without complaint, so Hosted
deployments are created there and driven by API afterwards, which works normally.

