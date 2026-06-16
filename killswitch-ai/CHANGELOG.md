# Changelog

All notable changes to killswitch-ai are documented here.
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.7] — 2026-06-16

### Changed
- Weekly email reports are now sent via the killswitch-ai API server (Resend) instead of
  direct SMTP. No SMTP configuration required — users only need a destination email address.
- `send_report_email()` no longer reads `smtp_host`, `smtp_user`, or `smtp_password` from
  the config. Existing `killswitch.yml` files with those fields continue to load without error.

---

## [0.1.6] — 2026-06-03

### Added
- Wizard (`killswitch init`) automatically enables anonymous telemetry when the user opts
  in to weekly email reports, since telemetry data is the source for those reports.

---

## [0.1.5] — 2026-06-03

### Fixed
- `killswitch -h` / `--help` now shows the standard help text with all
  commands and flags instead of opening the interactive menu.
- `killswitch` with no arguments also shows help (consistent with standard
  CLI conventions).
- `killswitch menu` continues to open the interactive menu as before.

---


## [0.1.4] — 2026-06-03

### Added
- **Expanded telemetry payload** (opt-in only): opted-in installs now report richer
  aggregated metadata to help prioritise development:
  - `decisions` — distribution of actions taken (allowed / blocked / redacted / paused)
  - `severity_counts` — aggregate finding-severity distribution (low / medium / high / critical)
  - `finding_categories` — broad security category counts (api_key, cloud_credential, private_key, …)
  - `detector_layers` — which detection layers fired (secret_pattern, entropy, prohibited_term, …)
  - `test_command_run` — whether `killswitch test` has been successfully executed
- **SQLite schema migration**: existing installs automatically gain the new columns on
  first upgrade — no manual action required.
- `normalize_decision`, `finding_type_to_category`, and `operation_to_type` helper
  functions for stable telemetry bucketing.

### Changed
- `record_call()` now accepts optional `severity_counts`, `finding_categories`, and
  `detector_layers` kwargs; callers that omit them continue to work unchanged.

### Notes
- No prompt text, secret values, file paths, or personally-identifying information is
  ever collected. Telemetry is disabled by default and only active when the user
  has explicitly opted in via the `killswitch.yml` config.

---

## [0.1.3] — 2026-05-28

### Added
- Initial public release.
- OpenAI and Anthropic provider hooks.
- Secret-pattern detection, high-entropy detection, and prohibited-term blocking.
- `killswitch test` CLI command.
- Anonymous opt-in telemetry (install_id, version, OS, command counts, agents, providers, modes).
