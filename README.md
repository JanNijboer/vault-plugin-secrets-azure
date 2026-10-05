# Vault Plugin: Azure Secrets Backend

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin generates revocable, time-limited Service Principals for Microsoft Azure.

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links
- [Vault Website](https://developer.hashicorp.com/vault/docs)
- [Azure Secrets Docs](https://developer.hashicorp.com/vault/docs/secrets/azure)
- [Vault Github Project](https://www.github.com/hashicorp/vault)

## Getting Started

This is a [Vault plugin](https://developer.hashicorp.com/vault/docs/plugins)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://developer.hashicorp.com/vault/docs/plugins).

## Usage

Please see [documentation for the plugin](https://developer.hashicorp.com/vault/docs/secrets/azure)
on the Vault website.

### Credential issuance retries

For newly created applications, propagation retries are scoped separately to
service principal creation and password creation, within an 80-second budget
(or an earlier request deadline). Only specific Graph application/reference
propagation errors are retried; generic permission errors are returned immediately.
A password retry uses the same verified service principal, never creates another
one, and preserves the requested password expiration.

Application creation and application/service principal password POSTs, as well
as service principal creation, disable the Graph SDK's automatic 429/503/504
retries. SDK authentication challenges, compression negotiation and redirects
retain their existing handling. Transport failures, server errors, and incomplete
service principal or password responses are not replayed: a POST may have succeeded
despite the error, and Graph returns a generated password's secret only once. An "already in use"
error is returned without adopting an existing service principal. Errors from
service principal issuance identify the failed POST stage.

Group membership failures identify the target group and service principal, plus
the Graph HTTP status, error code, and response `request-id` when available.
The request ID falls back to `innerError.request-id` if the response header is
absent; `innerError.date` is reported in UTC when available.
These identifiers help correlate failures with Microsoft support; credentials
and other response headers are not included.
Group membership retries match typed Graph status/code pairs: 404 with
`Request_ResourceNotFound`, or 400 with `Request_BadRequest`/`BadRequest` and a
recognized missing-reference message. Each group has an 80-second retry budget
(or an earlier caller deadline); only that membership operation is repeated.
Timeout errors retain the last retryable error for diagnosis.

This patched build also experimentally retries group-membership HTTP 403 errors
only when the code is `Authorization_RequestDenied` and the message is exactly
`Insufficient privileges to complete the operation.` (case-insensitive, ignoring
surrounding whitespace). Up to five such denials are allowed per group, with
2, 4, 8, and 16 seconds of backoff before the subsequent attempts, within the
same 80-second budget. Other permission errors are returned immediately. This
does not establish that the denial is caused by replication, and it can delay
reporting a permanent permission problem. No opt-in flag is required in this build.

Each authorization retry and final exhaustion is logged at warning level with
the group/SP IDs and Graph correlation details; recovery is logged at info level.
Only the failed membership is retried: earlier groups, application creation, SP
creation, and password creation are not repeated. A recognized duplicate-member
response is accepted only after a GET of that exact group/SP membership returns
the matching SP ID. A failed, missing, or mismatched verification returns an error,
not credentials. The existing SDK HTTP retry policy for group operations is unchanged.

Every credential-read handler logs one `credential issuance summary`: info on
success, warning on failure, including path, role, request ID, elapsed milliseconds,
failed stage, and counts of SP-create, SP-password, role-assignment, group-propagation,
and group-authorization retries. Counts are additional plugin attempts actually
started, summed across the request; they exclude SDK HTTP retries and cancelled
backoff waits. Application creation and application-password POSTs are not retried.
Verified duplicate memberships have a separate count and an info log,
`group membership already present and verified`, even without a plugin retry.
These logs contain no credentials or response bodies. A successful summary means
the plugin returned credentials to Vault, not proof of lease persistence or delivery
to the caller. Summary timing includes storage operations and cleanup on failure.

After a password failure, the plugin attempts to delete the verified service
principal with a separate, bounded cleanup context. The application WAL remains
for Vault's rollback, which deletes the application and relies on Azure to
cascade deletion to its service principal. Rollback is eligible after 10 minutes;
failed cleanup can be retried until the WAL expires after 24 hours. This is not
an immediate-cleanup guarantee. Application creation precedes the WAL write, so
a lost application-create response or a failed WAL write can still leave an
untracked application requiring operator cleanup.

### Repeatable cleanup

Dynamic credential revocation first deletes the application, then cleans up
role assignments, group memberships and the service principal. Deleting the
application also soft-deletes its service principal, but purging the application
does **not** purge the service principal. When `permanently_delete` is set, both
objects require a permanent delete from `/directory/deletedItems`.

After a successful soft delete, the purge is attempted immediately. Shortly
after a soft delete, Entra ID can answer both the purge and a deleted-items GET
with 403 `Authorization_RequestDenied` / `Insufficient privileges to complete
the operation.`. Application-purge tests succeeded after 10- and 30-second waits;
these observations do not prove every such 403 is propagation rather than a
permission problem. That exact
403, a purge 404 (not yet visible), transient network errors and HTTP
408/500/502/503/504 are retried inline. If the purge has not succeeded when the
inline budget runs out, or fails with any other error, the object is already
soft-deleted, so revocation succeeds and the purge is recorded as a
`purgeDeleted` WAL entry. Vault retries WAL entries after at least 10 minutes;
each attempt is one purge request, where 204 or 404 completes the entry. The
entry expires after 24 hours. A failed attempt after expiry logs the object ID
and drops the entry, possibly leaving the object for Entra ID's retention policy.
An exhausted request/pass deadline does not by itself expire a WAL entry.

A soft-delete 404 or ambiguous transport/server failure during revoke or WAL
rollback first attempts a direct purge, if permanent deletion is enabled.
A successful purge completes cleanup without requiring a deleted-items read.
An inconclusive result triggers a deleted-items GET validating the object ID and
type. Finding the object there establishes soft deletion. Other transient
failures are retried within the budget; soft-delete permission errors and invalid
responses fail. HTTP 429 is left for a later attempt rather than ignoring
`Retry-After`. A role with `permanently_delete=false` never attempts a purge.

**Age-based 404 fallback (heuristic, not proof):** after a typed soft-delete 404
and a deleted-items 404 or the exact 403 above, an object belonging to a lease at
least five minutes old can be accepted as absent only after three consecutive
typed active-object GET 404s, separated by one second. An active response, read
error, malformed response or cancellation prevents that acceptance. New leases
persist `issued_at`; old leases use Vault's supplied `Secret.IssueTime` where
available. Only when both are absent is the lease treated as old. Invalid
timestamps fail rather than silently enabling the fallback.

Heuristic acceptance logs a warning with the object ID, issue time and whether
the age was unknown. It also records a purge WAL when permanent deletion is
enabled. Long-lived replication faults can still produce a false absence;
neither five minutes nor repeated 404s guarantees that credentials are disabled.

Each object has a shared 10-second budget (or the caller's earlier deadline)
and at most four retry waits across all stages, with jittered exponential
waits of 0.5-1, 1-2, 2-4 and 4-8 seconds, capped so the last request starts at
least two seconds before the budget ends. The SDK's automatic retries are
disabled for these requests. Cancellation interrupts waits and prevents further
requests. Each resource-cleanup WAL callback has a five-second budget and no
inline exponential retries. The fallback's two one-second read intervals still
apply. Callbacks do not start network work when less than one second remains
in the pass. They return an error, not success, so unprocessed WALs are retained.
ARM role-assignment deletes also disable SDK retries.

Failed role-assignment deletes are written individually to `appRoleAssign`
WAL entries using their full ARM IDs; successful deletions are not queued.
Uncertain/failed SP soft deletes get `servicePrincipalCleanup` WAL entries,
including when application deletion has cascaded to the SP. Failed SP purges
use `purgeDeleted`, just like app purges. Group cleanup remains warning-only;
there is no group-membership WAL. **Any required WAL-write failure fails the
revocation** rather than silently abandoning housekeeping.

Failed issuance WALs now record the SP ID once creation completes. Legacy WALs
and ambiguous SP-creation failures discover principals by app ID in both active
and deleted collections, following pagination and validating every returned app
ID before deletion. Lookup failures retain the application WAL; the app delete
is still attempted. This lookup requires access to both collections. Old
`appCreate`, `appRoleAssign` and `purgeDeleted` entries remain readable.

Cleanup remains best effort over time, not an unlimited delivery guarantee:
the existing 24-hour WAL expiry remains, and operators must monitor expiry/error
logs. The framework controls traversal order and the mount-wide rollback
deadline; bounding individual callbacks reduces blocking but does **not** solve
starvation in a severely overloaded pass. Vault 1.21.4 limits expiration-manager
revocation retries (`maxRevokeAttempts = 6`) before marking a lease irrevocable;
that is separate from plugin WAL retries. These changes neither grant Graph
permissions nor guarantee immediate consistency. Removing credentials also
does not guarantee invalidation of access tokens already issued.

This plugin is currently built into Vault and by default is accessed
at `azure`. To enable this in a running Vault server:

```sh
$ vault secrets enable azure
Success! Enabled the azure secrets engine at: azure/
```

## Developing

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine
(version 1.17+ is *required*).

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).
Next, clone this repository into
`$GOPATH/src/github.com/hashicorp/vault-plugin-secrets-azure`.
You can then download any required build tools by bootstrapping your
environment:

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://developer.hashicorp.com/vault/docs/configuration#plugin_directory)
in the Vault config used to start the server.

```json
plugin_directory = "path/to/plugin/directory"
```

Start a Vault server with this config file:
```sh
$ vault server -config=path/to/config.json ...
...
```

Once the server is started, register the plugin in the Vault server's [plugin catalog](https://developer.hashicorp.com/vault/docs/plugins/plugin-architecture#plugin-catalog):

```sh

$ vault plugin register \
        -sha256=<SHA256 Hex value of the plugin binary> \
        -command="vault-plugin-secrets-azure" \
        secret \
        azure
...
Success! Data written to: sys/plugins/catalog/azure
```

Note you should generate a new sha256 checksum if you have made changes
to the plugin. Example using openssl:

```sh
openssl dgst -sha256 $GOPATH/vault-plugin-secrets-azure
...
SHA256(.../go/bin/vault-plugin-secrets-azure)= 896c13c0f5305daed381952a128322e02bc28a57d0c862a78cbc2ea66e8c6fa1
```

Enable the plugin backend using the secrets enable plugin command:

```sh
$ vault secrets enable -plugin-name='azure' plugin
...

Successfully enabled 'plugin' at 'azure'!
```

### Azure Environment Setup

A Terraform [configuration](bootstrap/terraform) is included in this repository that
automates provisioning of Azure resources necessary to configure the secrets engine.
By default, the resources are created in `westus2`. See [variables.tf](bootstrap/terraform/variables.tf) 
for the available variables.

Before applying the Terraform configuration, you'll need to:

1. [Authenticate](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs#authenticating-to-azure)
   the Terraform provider to Azure

The Terraform configuration will create:

* An app registration with necessary API permissions
* A service principal with necessary role assignments

To provision the Azure resources, run the following:

```sh
$ make setup-env   
```

The `local_environment_setup.sh` file will be created in the `bootstrap/terraform`
directory as a result of running `make setup-env`. This file contains environment
variables needed to configure the secrets engine. The values can also be accessed
via `terraform output`.

Once you're finished with plugin development, you can run the following to
destroy the Azure resources:

```sh
$ make teardown-env   
```

### Configure Plugin

A [scripted configuration](bootstrap/configure.sh) of the plugin is provided in
this repository. You can use the script or manually configure the secrets engine
using documentation.

To apply the scripted configuration, first source the environment variables generated by
the Azure environment setup:

```sh
$ source ./bootstrap/terraform/local_environment_setup.sh
```

Next, run the `make configure` target to register, enable, and configure the plugin with
your local Vault instance. You can specify the plugin name, plugin directory, and mount
path. Default values from the Makefile will be used if arguments aren't provided.

```sh
$ PLUGIN_NAME=vault-plugin-secrets-azure \
  PLUGIN_DIR=$GOPATH/vault-plugins \
  PLUGIN_PATH=local-secrets-azure \
  make configure
```

#### Tests

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the tests.

To run the tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='--run=TestConfig'
```

#### Acceptance Tests

This repository contains acceptance tests that interact with real Azure resources. There
are acceptance tests written in Go and [bats](https://bats-core.readthedocs.io/en/stable).

##### Go

To run the Go acceptance tests, run the following:

```sh
$ make testacc 
```

##### Bats

Acceptance tests requires Azure access, and the following to be installed:
- [Docker](https://docs.docker.com/get-docker/)
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [Terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli)
- [bats](https://bats-core.readthedocs.io/en/stable)

_You will need to be properly logged in to Azure with your subscription set. See
['Azure Provider: Authenticating using the Azure CLI'](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/azure_cli)_
for more information.

```sh
$ make test-acceptance AZURE_TENANT_ID=<your_tenant_id>
```

Setting `WITH_DEV_PLUGIN=` will use the provided builtin plugin. The default behavior is to build and register
the plugin from the working directory.

```sh
$ make test-acceptance AZURE_TENANT_ID=<your_tenant_id>
```

Running tests against Vault Enterprise requires a valid license, and specifying an enterprise docker image:

```sh
$ make test-acceptance AZURE_TENANT_ID=<your_tenant_id> \
  VAULT_LICENSE=........ \
  VAULT_IMAGE=hashicorp/vault-enterprise:latest
```

The `test-acceptance` make target also accepts the following environment based directives:

* `TESTS_FILTER`: a regex of Bats tests to run, useful when you only want to run a subset of the tests.
