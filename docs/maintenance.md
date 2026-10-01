# Maintained v1 crypto11 patch

Base: upstream stable v1.6.8 (`9fabe6478ebf32c8aadeae5ccd6d632269175145`). The module declaration remains `github.com/eclipse-keypont/crypto11`; consumers replace it with an immutable revision of `github.com/cpoile/crypto11`.

The production patch preserves native errors in four AES-GCM wrappers, identifies returned Seal operation errors with `*SealError`, and releases the persistent session before the module reference when Configure fails. `cipher.AEAD` signatures, the session pool, and shared module reference counting remain unchanged. Invalid Seal nonce lengths and arbitrary underlying panics are not marked. Callers recovering Seal must assert the exact marker type and re-panic everything else. Error text is diagnostic, not a safe user response.

CloseSession failure does not replace the primary initialization error and is not retried. A device session may remain until the final module owner closes; no stronger native-call cancellation or recovery is promised. Do not Logout or CloseAllSessions during rollback.

## Qualification

Run from this repository (dependency tests are not run by a consumer):

```sh
docker build --platform linux/amd64 -t crypto11-fixture -f testdata/softhsm/Dockerfile testdata/softhsm
docker run --rm --platform linux/amd64 -v "$PWD:/source:ro" crypto11-fixture bash /source/testdata/softhsm/run.sh
```

The fixture pins Ubuntu 24.04 by digest and SoftHSM 2.6.1-2.2ubuntu3. It provisions isolated token1/token2 stores and reconciles test configuration with generated PINs. It runs required tagged native tests with the real forwarding module, then the broad race suite against a fresh store. Missing dependencies fail. The shim measures successful session transitions and live handles; failed-login tests inject no fault. Other cases inject only setup, crypto and close failures. The shim stays in testdata and its Go control package requires `crypto11_testshim`.

`testdata/softhsm/prepare.py` and `provision` are reusable operator fixtures for the dependent KMD installed suite. They are never production provisioning APIs. Never export fixture config, token stores or raw native error text as test artifacts.

Keep future patches bounded against this base. Compare upstream fixes before adopting them, retain the native regression, and propose cleanup/error fixes upstream separately. Upstream PR144 is related cleanup work; it is not assumed released. Ed25519, context reconnection policy and migration to v2 are outside this patch.
