# setup-tbzl

Autoconfigure a Bazel build for the tbzl remote-execution plane: name your tenant,
and the endpoint, credentials, exec properties and tuning are fetched from the
platform at runtime rather than transcribed into your workflow.

⏰ **Scaffold.** The Action, the `tbzl-setup` binary and its test suite land in the
first pull request. This commit exists so the secret-scanning merge gate is in force
*before* any content arrives — see `.github/workflows/ci.yml`.
