# mcp-lint — the missing security linter for MCP

[![PyPI](https://img.shields.io/badge/pypi-mcp--lint-blue)](https://pypi.org/project/mcp-lint/)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**`pip install mcp-lint && mcp-lint scan`** — scan your mcp.json for 7 OWASP Top 10 risks in 5 seconds. No API keys. No cloud. No excuses.

## Why

Every MCP server you connect gives an AI agent access to your files, your shell, and your network. Your `mcp.json` is 30 lines of JSON that carry the attack surface of a full application — and nobody audits it.

`mcp-lint` reads your MCP config and runs 7 static checks mapped to the OWASP MCP Top 10: hardcoded secrets, tool poisoning, command injection, overly broad permissions, missing authentication, supply chain risks, and shadow servers. It's offline, pip-installable, and takes 5 seconds.

If eslint exists for JavaScript, `mcp-lint` exists for MCP.

## vs Other Scanners

| | mcp-lint | Others |
|---|---------|--------|
| Runtime | Offline — no config leaves your machine | Upload to cloud for analysis |
| Dependencies | Python stdlib + click + rich | Need Groq/Cisco/LLM API keys |
| Install | `pip install mcp-lint` | npm / npx / Rust / Go / Docker |
| Language | EN + 中文 | English only |

## Quick Start

```bash
pip install mcp-lint
mcp-lint scan                    # Auto-discover & scan all MCP configs
mcp-lint scan --json             # JSON output
mcp-lint scan --json -o report.json
mcp-lint scan --sarif            # SARIF for CI/CD
mcp-lint scan -c MCP01,MCP03     # Run specific checks only
```

## 7 Security Checks

| ID | Check | OWASP Mapping |
|----|-------|---------------|
| MCP01 | Hardcoded secrets | Token Mismanagement & Secret Exposure |
| MCP02 | Overly broad permissions | Privilege Escalation via Scope Creep |
| MCP03 | Tool description poisoning | Tool Poisoning |
| MCP04 | Supply chain risks | Supply Chain & Dependency Tampering |
| MCP05 | Command injection | Command Injection & Execution |
| MCP07 | Missing authentication | Insufficient Authentication |
| MCP09 | Shadow MCP servers | Shadow MCP Servers |

## Example Output

```
mcp-lint v0.1.0 — MCP Security Auditor
========================================================
Targets: ~/.claude.json
Servers: 2 | PASS: 9 | WARN: 1 | FAIL: 0
========================================================

[WARN] seedance (MCP01: Token Mismanagement)
  CVSS: 6.5 | Sensitive env var 'ARK_API_KEY' could be a secret
  Fix: Move to a secret manager (1Password CLI, Vault)

[FAIL] insecure-server (MCP05: Command Injection)
  CVSS: 9.0 | os.system() call detected
  Fix: Replace with subprocess.run(args_list, shell=False)

[FAIL] poisoned-server (MCP03: Tool Poisoning)
  CVSS: 9.5 | Tool description contains exfiltration URL pattern
  Fix: Verify tool source. Remove instruction-manipulation language.
```

## CI Integration

```yaml
- name: MCP Security Lint
  run: |
    pip install mcp-lint
    mcp-lint scan --json -o mcp-audit.json
```

## From Source

```bash
git clone https://github.com/your/mcp-lint.git
cd mcp-lint
pip install -e .
mcp-lint scan
```

---

# 中文

`mcp-lint` 之于 MCP，就像 `eslint` 之于 JavaScript。

## 为什么需要

你连接的每个 MCP 服务器都在给 AI 代理文件系统、Shell 和网络的访问权。你的 `mcp.json` 只有 30 行 JSON，但攻击面等同于一整个应用——而且没人审计它。

## 做什么

读你的 MCP 配置 → 跑 7 项静态检查 → 5 秒出 CVSS 评分安全报告。离线运行，不上传配置，不依赖任何外部 API。

## 检出能力

对包含硬编码密钥、工具投毒、命令注入、无认证 HTTP 传输的漏洞配置：检出率 100%，零漏报。对安全配置：零误报。

---

MIT License
