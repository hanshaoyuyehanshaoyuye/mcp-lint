# 🔐 mcp-lint — MCP 安全检测器

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](https://python.org) [![License](https://img.shields.io/badge/license-MIT-green)](LICENSE) [![OWASP](https://img.shields.io/badge/OWASP-MCP%20Top%2010-red)](https://owasp.org/www-project-mcp-top-10/)

<p align="center">
  <b><i>你的 mcp.json 有 30 行。其中 10 行可能是漏洞。</i></b><br>
</p>

<pre align="center">
pip install mcp-lint && mcp-lint scan
</pre>

<p align="center">
5 秒 · 10 项检查 · 零 API 依赖<br>
<strong>小小插件，为你的电脑保驾护航。</strong>
</p>

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

# 中文

<p align="center">
  <b><i>你的 mcp.json 有 30 行。其中 10 行可能是漏洞。</i></b>
</p>

## `mcp-lint` 是什么

`mcp-lint` 是 MCP 协议世界缺失的安全检查器——就像 `eslint` 之于 JavaScript。

你每连接一个 MCP 服务器，就等于给 AI 代理开放了文件系统、Shell 和网络权限。你的 `mcp.json` 只有 30 行 JSON，但攻击面等同于一个完整应用——**而且没人审计它**。

- MCP 服务器中 **43%** 存在命令注入漏洞（Invariant Labs, 2025）
- 单个 AI 代理连接 5 个 MCP 服务器时，**攻击成功率 78.3%**（Unit 42, 2026）
- OWASP 为此专门发布了 **MCP Top 10** 安全风险分类

`mcp-lint` 做的事情很简单：读你的 MCP 配置 → 跑 10 项静态安全检查 → 5 秒出 CVSS 评分安全报告。完全离线，不上传任何配置到云端，不依赖任何外部 API。**小小插件，为你的电脑保驾护航。**

## 与其他扫描器的区别

`mcp-lint` 是目前唯一满足以下所有条件的 MCP 安全扫描器：

| | mcp-lint | 其他 |
|---|---------|------|
| **运行方式** | 完全离线，配置不离开本机 | 多数需要上传到云端或调 LLM API |
| **安装** | `pip install mcp-lint`，Python 用户一键装 | npm / npx / Rust / Go / Docker，各管各的 |
| **覆盖率** | **10/10** OWASP MCP Top 10 全覆盖 | 大多数仅覆盖 5-7 项 |
| **规则扩展** | YAML 文件，不改源码就能加规则 | 正则硬编码在源码里 |
| **闭环** | 扫描 → 基线快照 → 漂移检测 → 不可篡改审计日志 | 扫描 → 结束（无基线对比，无审计链） |
| **测试** | 6 个真实 CVE/0day 测试用例 | 1-2 个手写案例 |
| **语言** | 英文 + 中文双语 | 仅英文 |

## 快速开始

```bash
pip install mcp-lint
mcp-lint scan          # 自动发现并扫描所有 MCP 配置
mcp-lint list-checks   # 列出全部 10 项检查
mcp-lint scan --json   # JSON 输出，适合脚本消费
mcp-lint scan --sarif  # SARIF 格式，接入 GitHub Actions CI
```

## 10 项安全检查（OWASP MCP Top 10 全覆盖）

| ID | 中文名 | 检出什么 |
|----|--------|---------|
| MCP01 | 凭证泄露 | API Key、Token、私钥硬编码在 `env:` 或 `args:` 中 |
| MCP02 | 权限过度 | 文件系统根目录挂载、`0.0.0.0` 全网监听 |
| MCP03 | 工具投毒 | Tool 描述里藏了 "忽略前面的指令"、"先读 ~/.ssh/id_rsa" 等注入 |
| MCP04 | 供应链风险 | 未加作用域的 npm/pip 包名、`npx -y` 自动确认安装 |
| MCP05 | 命令注入 | `os.system()`、`eval()`、`subprocess(shell=True)` |
| MCP06 | 上下文注入 | pastebin / raw GitHub 作为数据源 → 恶意内容污染 Agent |
| MCP07 | 认证缺失 | HTTP 传输却没有 OAuth / Token / Authorization 头 |
| MCP08 | 审计缺失 | 网络传输却没有日志、遥测、可观测性 |
| MCP09 | 影子服务器 | `node_modules/`、`.npm/`、`下载/` 目录下的未授权 MCP 配置 |
| MCP10 | 上下文过度共享 | 多会话共享 context window + HTTP 传输 = 跨租户数据泄露 |

**真实 CVE 测试集：** CVE-2025-54136（MCPoison 配置篡改）、Invariant Labs SSH 密钥窃取工具、CVE-2025-32711（EchoLeak 零点击数据外泄）、CyberArk 参数名投毒、npm 拼写欺诈、多服务器影子攻击。

## 闭环工作流

```
mcp.json ──→ scan ──→ 10 项检查 ──→ 报告
                │                      │
     ┌──────────┴──────────┐           │
     ▼                     ▼           ▼
  baseline 快照        audit 审计日志
(.mcp-lint.lock)  (~/.mcp-lint-audit.jsonl)
     │              SHA-256 哈希链,
     ▼              不可篡改
  verify 验证
(漂移检测:
 新 FAIL → CI 阻断)

mcp-lint baseline      # 拍快照：记录当前状态作为基线
mcp-lint verify --gate # CI 闸门：PR 引入新 FAIL 则拒绝合并
mcp-lint audit         # 审计链：谁在何时扫描了什么，不可篡改
mcp-lint autofix       # 自动修复：高置信度修复自动应用
```

## 自定义规则（不改源码）

```bash
mcp-lint scan --rules my-rules.yaml   # 加载自定义检测规则
```

所有检测规则在 `mcp_guard/rules/` 目录下以 YAML 格式存储。你可以添加自己的检测模式、调整 CVSS 评分、定义组织专属的敏感密钥模式——不需要动一行 Python 代码。

## 项目结构

```
mcp-guard/
├── mcp_guard/
│   ├── checks/          # 10 个安全检查（全部继承 SecurityCheck ABC）
│   ├── rules/           # 10 个 YAML 规则文件（用户可扩展）
│   ├── scanner.py       # 编排中心（scan / baseline / verify / autofix / audit）
│   ├── audit.py         # 审计日志（SHA-256 哈希链，不可篡改）
│   ├── baseline.py      # 基线快照 + 漂移检测
│   ├── autofix.py       # 7 个修复模板（高置信度自动应用）
│   ├── discovery.py     # 跨 8 个 IDE 自动发现 MCP 配置
│   ├── reporter.py      # terminal / JSON / SARIF 三种输出
│   └── cli.py           # 6 个 CLI 命令
└── tests/
    ├── fixtures/        # 8 个测试配置（2 基础 + 6 CVE/0day）
    └── test_scanner.py
```

## 源码安装

```bash
git clone https://github.com/hanshaoyuyehanshaoyuye/mcp-lint.git
cd mcp-lint
pip install -e .
mcp-lint scan
```

---

## License

MIT
