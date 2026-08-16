# orders-api

Scaffolded via the Port golden path.

## Snyk → Port
`lodash@4.17.20` is pinned **on purpose** so Snyk has findings. The workflow
`.github/workflows/snyk-to-port.yml` runs `snyk test` and upserts unique issues
onto the Port `vulnerability` blueprint, related to service `orders_api`.

Repo secrets required: `SNYK_TOKEN`, `PORT_CLIENT_ID`, `PORT_CLIENT_SECRET`.
