# `cargo xtask plugin-version-check`

`cargo xtask plugin pending` compares a port's version with the beta index and nothing else: a
port whose `plugin.toml`, `Cargo.toml` or `src/` changed but whose version did not would be
skipped by the release, or its package would differ from the one the index describes. This check
closes that gap.

It compares the working tree with the last `plugins-*` tag reachable from `HEAD`
(`git describe --tags --match 'plugins-*'`). For every port that exists at that tag, if
`plugin.toml` still has the tag's `version` and any of `plugins/<port>/plugin.toml`,
`plugins/<port>/Cargo.toml` or `plugins/<port>/src/` differs from the tag, the port is reported
and the exit status is 1. Everything else (a changed `registry.toml`, a port that is new since
the tag, the shared crates) is not an error. Whether `Cargo.toml` and `plugin.toml` versions
agree is a `plugin pack` rule, not this check's.

Without a tag in the checkout the command prints `NOTICE: no tag matching plugins-* ...` and
exits 0: a shallow clone without tags checks nothing. CI therefore fetches the tags: the `test`
job of `.github/workflows/ci.yml` checks out with `fetch-depth: 0` and runs the check on Linux
(after the plugin operations lint). Run it locally before bumping versions for a release.
