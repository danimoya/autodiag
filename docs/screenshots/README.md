# GUI screenshots

Captured from disposable Oracle 23ai and 26ai testbeds. Hostnames, addresses and local paths are masked in the browser before capture; underlying case data is unchanged. Frames show the first viewport, not the entire scrollable page.

[Bootstrap guide](../gui-bootstrap.md) · [Animated tour](tour.webp)

| Page | Screenshot |
|---|---|
| Target inventory: both Oracle releases | [01-targets.png](01-targets.png) |
| 23ai target overview | [02-target-23ai.png](02-target-23ai.png) |
| 26ai target overview | [03-target-26ai.png](03-target-26ai.png) |
| 23ai ADR problems and diagnosis actions | [04-problems-23ai.png](04-problems-23ai.png) |
| 26ai ADR problems and diagnosis actions | [05-problems-26ai.png](05-problems-26ai.png) |
| Incidents for a repeated ORA-600 | [06-incidents.png](06-incidents.png) |
| Alert-log statistics and filtering | [07-alert-log.png](07-alert-log.png) |
| Case list and creation form | [08-cases.png](08-cases.png) |
| Case evidence, findings and report actions | [09-case.png](09-case.png) |
| Parsed incident trace | [10-incident-trace.png](10-incident-trace.png) |
| Paged raw trace lines | [11-raw-lines.png](11-raw-lines.png) |
| Comparison of two real incident stacks | [12-stack-diff.png](12-stack-diff.png) |
| Parsed 10046 SQL trace | [13-sql-trace.png](13-sql-trace.png) |
| Normal versus anomalous 10046 profiles | [14-sql-profile-diff.png](14-sql-profile-diff.png) |
| DBA report | [15-dba-report.png](15-dba-report.png) |
| Oracle Support SR draft | [16-sr-report.png](16-sr-report.png) |
| Live LLM diagnosis: 23ai | [17-diagnosis-23ai.png](17-diagnosis-23ai.png) |
| Live LLM diagnosis: 26ai | [18-diagnosis-26ai.png](18-diagnosis-26ai.png) |
| Interactive REST API documentation | [19-api-docs.png](19-api-docs.png) |

Raw file/Markdown downloads, JSON endpoints and the `/` redirect are not separate GUI screens. API documentation is included. POST actions return to the case or report pages shown here.

## Regenerate

Install Playwright in your development environment and Chromium (`npx playwright install chromium`), plus `npm install -g sharp-cli`. Keep the capture configuration and login file outside the repository.

The capture configuration has `credentialsFile` (JSON with `url`, `username`, `password`), `pages` (ordered `{name, caption, path, waitFor?}` objects using your current case/artifact/report IDs), and optional `replacements` (literal `[from, to]` pairs). Use only disposable test data.

```bash
node docs/screenshots/capture.mjs /private/capture-config.json
node docs/screenshots/build-tour.mjs
```

Inspect every PNG for sensitive data before committing. The builder verifies frame dimensions, animation count, 3.5-second delays, infinite looping and a 5 MiB size budget. The tour follows the imported `repo-carousel` skill; static frames are the non-animated alternative.
