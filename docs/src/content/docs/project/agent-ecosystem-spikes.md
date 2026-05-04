---
title: Agent Ecosystem Spikes
description: Research spikes for agent telemetry standards, skills packaging, and agent supply chain changes.
---

Last reviewed: May 4, 2026.

Two ecosystem changes matter for the agentcontainers roadmap:

- Agent telemetry is converging around OpenTelemetry-compatible conventions for GenAI, agents, tools, retrieval, metrics, and events.
- Agent skills are becoming portable filesystem packages with instructions, scripts, references, assets, and lightweight metadata.

Both changes are useful, but both create policy surfaces. Telemetry can leak prompts, tool arguments, files, canaries, credentials, and workflow topology. Skills can bundle executable code and procedural instructions that agents load and run on demand.

## Spike: Agent Telemetry

OpenTelemetry now has development-status GenAI semantic conventions for model spans, agent spans, events, metrics, OpenAI, Anthropic, AWS Bedrock, Azure AI Inference, and MCP. The GenAI agent conventions define operations such as `create_agent`, `invoke_agent`, and `execute_tool`, with attributes for agent identity, conversation IDs, data sources, model names, provider names, and server endpoints.

OpenInference is another important ecosystem signal. It is built on OpenTelemetry and standardizes spans for AI workloads such as LLM calls, agent reasoning steps, tool invocations, retrieval, embeddings, chains, and rerankers.

OpenAI's Agents SDK also ships built-in tracing. It records agent runs, LLM generations, tool calls, handoffs, guardrails, and custom spans by default, with processors that can export traces to OpenAI or other destinations.

### What agentcontainers needs to learn

| Question | Why it matters |
|---|---|
| Which telemetry schema should agentcontainers emit? | OTel GenAI is the likely baseline, but it is still marked development. OpenInference may matter for compatibility with AI observability tools. |
| Should enforcer events map to OTel spans/events? | A single trace should be able to explain model call, tool call, shell command, blocked network egress, denied file open, and approval decision. |
| Is telemetry egress a capability? | Yes. Trace exporters can carry sensitive payloads to external systems and should require explicit policy. |
| How do we redact by default? | OTel warns that instructions, inputs, outputs, and tool arguments can be sensitive. agentcontainers should make content capture opt-in and redacted by default. |
| Can we correlate without leaking? | We need stable run/session/approval IDs that correlate events without storing prompts, secrets, or full tool arguments. |

### Roadmap implications

- Add `agent.telemetry` policy: exporter endpoints, provider, sampling, content capture, redaction, and retention.
- Add a local OTLP collector fixture for `dojo telemetry`.
- Export enforcer/audit events as OTel-compatible events or spans.
- Map blocked operations to low-cardinality attributes: domain, path class, rule ID, cgroup/container/session, and redacted executable.
- Treat trace exporters like network and credential capabilities.
- Add tests proving prompts, canaries, env values, and auth files are not exported unless content capture is explicitly enabled.

## Spike: Agent Skills

Agent Skills are now described as an open, portable format: a skill is a directory with a required `SKILL.md` containing YAML frontmatter and Markdown instructions. Skills may include scripts, references, assets, templates, and other resources. Agents discover skills by loading lightweight metadata first, then load full instructions and supporting files only when relevant.

Claude Code, Claude API/SDK, GitHub Copilot, Codex, and other coding agents are moving toward this pattern. GitHub documents project skills in `.github/skills`, `.claude/skills`, or `.agents/skills`, and personal skills under `~/.copilot/skills` or `~/.agents/skills`. The OpenAI skills catalog uses curated, experimental, and system skills for Codex.

The MCP Registry is a parallel supply-chain signal. It is a preview metadata registry for public MCP servers, not a package registry. It points to code or images in npm, PyPI, NuGet, Docker/OCI, and other registries. It verifies namespace ownership and package linkage, but delegates actual code scanning to package registries and downstream aggregators.

### What agentcontainers needs to learn

| Question | Why it matters |
|---|---|
| Are skills data, code, or policy? | They are all three: instructions, executable scripts, bundled assets, and permission hints. |
| Can skills carry capability manifests? | They should. A skill should declare expected shell commands, network egress, filesystem access, secrets, MCP servers, and telemetry needs. |
| How should skills be packed? | Filesystem folders are ergonomic, but release-grade distribution needs signed bundles, SBOMs, provenance, digest pinning, and lockfile coverage. |
| Is `allowed-tools` enough? | No. It is useful metadata, but agentcontainers needs runtime enforcement independent of agent-side tool hints. |
| How do MCP servers and skills relate? | Skills can instruct agents to use MCP servers; MCP registry entries can point to executable packages. The combined supply chain needs unified policy. |

### Roadmap implications

- Extend `skillbom` into a broader skill package manifest with files, scripts, assets, declared capabilities, licenses, hashes, and provenance.
- Package skills as OCI artifacts or attach them as OCI referrers so they can be signed, pinned, mirrored, and verified.
- Add a lockfile section for skills and MCP registry metadata, including source URL, digest, version, license, capabilities, and verification status.
- Add `agent.capabilities.skills` to control which skills are mounted, activated, or allowed to execute bundled scripts.
- Treat skill scripts like executable supply chain components: default deny unless their hash and command path are approved.
- Add a `dojo skills-supply-chain` profile that tries malicious skill instructions, scripts, symlinks, hidden files, network installers, and MCP package indirection.
- Support private skills and MCP registries without leaking private metadata to public registries.

## Near-Term Spike Plan

| Spike | Deliverable | Acceptance criteria |
|---|---|---|
| Telemetry inventory | Compare OTel GenAI, OpenInference, and OpenAI Agents SDK traces against agentcontainers audit events. | A proposed `agent.telemetry` schema and a local OTLP collector test plan. |
| Telemetry safety | Define redaction and content-capture defaults. | Canaries, env values, auth files, prompts, and tool arguments are absent from exported traces by default. |
| Skills inventory | Compare Agent Skills spec, Claude Code skills, GitHub Copilot skills, and Codex skills catalog. | A compatibility table for skill locations, metadata fields, execution model, and package layout. |
| Skill supply chain | Define package and lockfile model for skills. | Draft skill manifest fields: source, digest, files, scripts, assets, license, SBOM, provenance, capabilities, and allowed execution. |
| MCP linkage | Map MCP Registry metadata into agentcontainers policy. | A decision on whether MCP registry entries become components, skills, tools, or a separate lockfile section. |

## Sources

- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [OpenTelemetry GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)
- [OpenTelemetry GenAI client spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/)
- [OpenInference specification](https://arize-ai.github.io/openinference/spec/)
- [OpenAI Agents SDK tracing](https://openai.github.io/openai-agents-python/tracing/)
- [Agent Skills overview](https://agentskills.io/)
- [Agent Skills specification](https://agentskills.io/specification)
- [Claude Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills)
- [GitHub Copilot agent skills](https://docs.github.com/en/copilot/concepts/agents/about-agent-skills)
- [OpenAI skills catalog for Codex](https://github.com/openai/skills)
- [MCP Registry](https://modelcontextprotocol.io/registry/about)
- [MCP Registry package types](https://modelcontextprotocol.io/registry/package-types)
