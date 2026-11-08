# Final fix: server + ports docs (fix/final-server-docs, FinalFixServerDocsM2)

Source: final-plugins-server.md (I1-I3, M1-M5) and final-plugins-ports.md (I1-I3, M1-M3).

- Server I1: `plugin_records` keeps one open chunk run and resets it on Recovery/Final/terminal frames like `replay`. Regression test `plugin_records_survive_a_torn_write_recovery_and_a_later_use_at_every_cut` (every 8th byte of the three failing ranges, every 53rd elsewhere; ~19 s). RED before the fix: 526 bad cuts ("records after recovery ... requires operator inspection").
- Server I2: a plugin use that cannot fit a segment/quota is refused (`audit-fact-too-long`, PermissionDenied, NotApplied) before `journal_touched`; `PLUGIN_MIN_SEGMENT_BYTES` (4640) is a config error when any grant has `plugin_bytes`. Tests: health stays Healthy, next plain use succeeds; config test. The older test `a_segment_too_small_for_a_plugin_use_refuses_before_writing_anything` now expects PermissionDenied (it pinned the old poisoning).
- Server I3 docs: 49 ids, token `sign` right + key in token keys + grant keys, torn write = `open` fails.
- M1 warn for `plugin_bytes` + `param:` profile; M2 tracing events (`oncl::plugin_grants`) + skipped-count line; M3 spent only after the journal accepted (`PluginTicketPolicy::accepted`, test); M5 `BytesGrant::check` takes the key, `key-mismatch` in the CLI (cli.md, unit test).
- M4 (refusal churn) not changed: accepted as a documented per-operation bound (not requested).
- Ports I1/I3/M2/M3 docs, I2 `cargo xtask plugin-version-check` (+ci.yml fetch-depth: 0 and step, docs/dev/plugin-version-check.md, tests on a temp git repo), M1 one `[[differences]]` line per other declaring port (rating1c's operations note is a `[[differences]]` entry).
