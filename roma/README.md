# Build and test with Roma

This composite action runs `roma build //...` followed by `roma test //...` by default in the checked-out workspace. A download, verification, build, or test failure fails the step. The action returns the installed executable path as the `executable` output. It does not configure caching or publish build artifacts.

Use a trusted job with checkout, Bash, GitHub CLI, `shasum`, and `tar`. Select the runner in the calling job. Keep the version, source commit, and digest together in reviewed configuration. The digest must identify the archive for that job's native platform.

| Input | Required value |
| --- | --- |
| `version` | Exact Roma release tag |
| `source` | Full source commit of that release |
| `sha256` | Independently pinned SHA-256 of the platform archive |
| `release-token` | Caller-supplied token with Contents read access to the private Roma repository |
| `build-args` | Optional build arguments, one per line. Defaults to `//...`. |
| `test-args` | Optional test arguments, one per line. Defaults to `//...`. |

The token is used for the archive download. The workflow must supply any credentials the build needs for private dependencies or remote execution separately. Use `contents: read` for checkout and grant any additional workflow permissions only where required. Never run the private download job for a fork pull request or under `pull_request_target`. The action also rejects these events.

During qualification, pin the reviewed action commit. Tomato Bazel assigns `FASTVERK_APP_ID` and `FASTVERK_APP_PRIVATE_KEY` to authorized repositories. The `rules_tla` credential probe confirmed that this App can mint a token limited to reading Roma releases.

```yaml
permissions:
  contents: read
jobs:
  roma:
    if: github.event_name == 'push'
    runs-on: boston-linux-x64-tbzl
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/create-github-app-token@v2
        id: roma_read
        with:
          app-id: ${{ secrets.FASTVERK_APP_ID }}
          private-key: ${{ secrets.FASTVERK_APP_PRIVATE_KEY }}
          owner: tomato-bazel
          repositories: roma
          permission-contents: read
      - uses: tomato-bazel/setup-tbzl/roma@15dbe9fffdac5a8a677e30444ef6671fc5406e84
        with:
          version: ${{ vars.ROMA_VERSION }}
          source: ${{ vars.ROMA_SOURCE }}
          sha256: ${{ vars.ROMA_LINUX_AMD64_SHA256 }}
          release-token: ${{ steps.roma_read.outputs.token }}
```

The example describes the draft interface. Use an archive for the selected runner only after it has been published and qualified on that platform.
