# @keel/lambda-common

Shared DB schema, auth, HTTP helpers, serialize, and Santa compile for Keel API Lambdas.

Used by:

- `keel-lambda-host`
- `keel-lambda-inventory`
- `keel-lambda-policies`
- `keel-lambda-events`
- `keel-lambda-santa`

Local workspaces use `"@keel/lambda-common": "file:../keel-lambda-common"`. For separate GitHub repos, publish this package (or git-submodule) and pin the version.

Schema must stay in sync with `control-panel/packages/db` migrations.
