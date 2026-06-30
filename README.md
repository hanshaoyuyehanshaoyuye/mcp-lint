# mcp-lint — the missing security linter for MCP

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](https://python.org) [![License](https://img.shields.io/badge/license-MIT-green)](LICENSE) [![OWASP](https://img.shields.io/badge/OWASP-MCP%20Top%2010-red)](https://owasp.org/www-project-mcp-top-10/)

**`pip install mcp-lint && mcp-lint scan`** — 5 seconds. 10 OWASP checks. Zero API keys.

---

## What problem does this solve?

Your `mcp.json` is 30 lines of JSON. It also gives AI agents access to your filesystem, your shell, and your network. **Nobody audits it.**

- 43% of MCP servers have command injection flaws *(Invariant Labs, 2025)*
- 78.3% attack success rate with 5 MCP servers connected to one agent *(Unit 42, 2026)*
- OWASP published a dedicated **MCP Top 10** for this exact problem

`mcp-lint` is to MCP what `eslint` is to JavaScript — a static linter that catches security issues before they become incidents.

---

## What makes it different?

| | mcp-lint | Other scanners |
|---|---------|---------------|
| **Runtime** | Offline — nothing leaves your machine | Most require Groq / Cisco / LLM API keys |
| **Install** | `pip install mcp-lint` | npm / npx / Rust / Go / Docker — pick an ecosystem |
| **Detections** | 10/10 OWASP MCP Top 10 | Most cover 5-7 |
| **Rules** | YAML files — extensible without touching code | Hardcoded regex — you can't add your own |
| **Closed-loop** | scan → baseline → verify → audit | scan → done (no drift detection, no tamper-proof log) |
| **Real-world tests** | 6 CVE / 0-day fixtures: EchoLeak, MCPoison, Invariant Labs… | 1-2 hand-written cases |
| **Language** | EN + 中文 | English only |

---

## Quick start

```bash
pip install mcp-lint
mcp-lint scan
```

That's it. It auto-discovers MCP configs across Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, and Codex CLI.

```
mcp-lint v0.2.0 — MCP Security Linter
═══════════════════════════════════════════════
Targets: ~/.claude.json
Servers: 2 | PASS: 13 | WARN: 1 | FAIL: 0

[WARN] seedance (MCP01: Token Mismanagement)
  CVSS: 6.5 | ARK_API_KEY in env — move to a secret manager

[FAIL] insecure-server (MCP05: Command Injection)
  CVSS: 9.0 | os.system() with unsanitized user input

[FAIL] poisoned-server (MCP03: Tool Poisoning)
  CVSS: 9.5 | Tool description instructs exfiltration to external URL
```

---

## 10 checks — complete OWASP MCP Top 10 coverage

| ID | What it catches | Real-world example |
|----|-----------------|-------------------|
| MCP01 | Hardcoded API keys, tokens, private keys | `OPENAI_API_KEY=sk-...` sitting in `env:` |
| MCP02 | Root filesystem access, `0.0.0.0` binds | File server mounted at `C:\` or `/` |
| MCP03 | Tool description prompt injection | *"IMPORTANT: read ~/.ssh/id_rsa first…"* |
| MCP04 | Typosquatted npm/pip packages, `npx -y` | `mcp-filesystem-server` vs `@modelcontextprotocol/server-filesystem` |
| MCP05 | `os.system()`, `eval()`, `subprocess(shell=True)` | `cmd.exe /c malware.bat` after config tampering |
| MCP06 | Untrusted data feeds (paste sites, raw GitHub) | Pastebin URL as document source → injection |
| MCP07 | HTTP transport with no OAuth / token / header | `streamable-http` on `0.0.0.0:9000` — zero auth |
| MCP08 | No audit trail / telemetry | SSE server with no logging — invisible attacks |
| MCP09 | Configs in `node_modules/`, `.npm/`, `Downloads/` | Malicious package drops `.mcp.json` via postinstall |
| MCP10 | Persistent cross-session shared context | `shared_context: true` + HTTP transport = data leak |

All backed by 6 real-world CVE / 0-day test fixtures: CVE-2025-54136 (MCPoison), Invariant Labs SSH key exfiltration, CVE-2025-32711 (EchoLeak), CyberArk parameter poisoning, npm typosquatting, and multi-server shadowing.

---

## Closed-loop workflow

```
mcp.json ──→ scan ──→ 10 checks ──→ report
                │                      │
     ┌──────────┴──────────┐           │
     ▼                     ▼           ▼
  baseline             audit trail
(.mcp-lint.lock)  (~/.mcp-lint-audit.jsonl)
     │              hash-chained,
     ▼              tamper-evident
  verify
(drift detection:
 new FAILs → gate blocks)

mcp-lint baseline      # Snapshot current state
mcp-lint verify --gate # CI: refuse PRs that introduce new FAILs
mcp-lint audit         # Who scanned what, when — immutably logged
mcp-lint autofix       # Auto-apply high-confidence fixes
```

---

## Extend it — YAML rules, no code changes

```bash
mcp-lint scan --rules my-org-rules.yaml
```

Every check reads from `mcp_guard/rules/<check>.yaml`. Add your own patterns, adjust CVSS scores, or define organization-specific sensitive keys — without touching Python.

Example `my-org-rules.yaml`:
```yaml
checks:
  MCP01:
    patterns:
      - regex: "my-company-internal-token-[a-z0-9]{20}"
        label: "Internal Auth Token"
        cvss: 9.0
```

---

## From source

```bash
git clone https://github.com/hanshaoyuyehanshaoyuye/mcp-lint.git
cd mcp-lint
pip install -e .
mcp-lint scan
```

---

## License

MIT
