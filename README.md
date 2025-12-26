# Prompt Injection Lab

**A prompt-injection red-teaming and defense framework for LLM agents with tool access.**

This project explores prompt injection as a **control-flow integrity problem** for language-based systems.
Rather than focusing on jailbreak prompts in isolation, it models how untrusted inputs can cause **unauthorized tool calls, capability escalation, and unsafe side effects** in agentic LLM applications.

---

## Why this project exists

Modern LLM applications increasingly rely on **agents** that:
- retrieve documents (RAG),
- call tools,
- take actions with real side effects.

Prompt injection becomes dangerous not because of text generation, but because it can:
- override system intent,
- manipulate tool selection,
- induce unsafe actions via untrusted contexts (documents, logs, tool output).

This repository is a **systems-first exploration** of that problem.

---

## Project goals

The long-term goals of this project are to:

- Build an **automated prompt-injection red-teaming framework**
- Implement **runtime defenses** for agent tool-calling
- Evaluate defenses using reproducible metrics (ASR, FPR, latency)
- Treat prompt injection as a **security and systems problem**, not just a prompt-engineering issue

---

## Current status (Day 2)

The repository currently implements a **minimal but fully functional agent runtime**, including:

### Agent runtime
- Deterministic agent loop (no LLM yet)
- Inputs:
  - system prompt
  - user prompt
  - context documents
  - tool schemas
- Outputs:
  - final_answer
  - or tool_call(name, args)

### Tool calling (simulated but realistic)

Three tools are implemented:

- search_docs(query): searches local documents and returns snippets
- get_email(id): retrieves an email from local JSON fixtures
- post_message(channel, text): simulates a side-effecting tool via local logs

### Full transcript logging

Every run logs:
- inputs
- agent decisions
- tool calls
- tool results
- final answers

Logs are written as structured JSONL files to:

runs/<run_id>.jsonl

This logging layer is the foundation for later benchmarking and attack analysis.

---

## Why no real LLM yet?

This is intentional.

The agent runtime, tool interfaces, and logging pipeline are validated **deterministically** before introducing a stochastic model.
This ensures that later failures can be attributed to:
- model behavior versus
- infrastructure or policy bugs.

LLMs will be integrated once the control-flow and evaluation scaffolding are stable.

---

## Quick start (2 minutes)

Requirements:
- Python 3.10+
- uv (fast Python environment manager)

Setup:
- uv sync
- source .venv/bin/activate

Run the demo agent:
- python -m backend.run_demo

Example prompts:
- search security policy
- show me the welcome email
- post this announcement: meeting at 5

Each run produces:
- terminal output showing tool usage
- a transcript file in runs/

---

## Repository structure

- backend/        agent runtime, tools, transcripts
- runtime_guard/  upcoming policy engine and detectors
- attacks/        upcoming attack templates and generators
- eval/           upcoming benchmarking harness
- docs/           design specs and notes
- runs/           execution transcripts (JSONL)

---

## Roadmap

Upcoming milestones:
- Day 3–4: Trust boundaries and untrusted-context tagging
- Day 5: Benchmark harness and baseline metrics
- Day 6–7: Injection detectors and policy enforcement
- Day 8+: Automated adaptive attack generation

Later:
- Real LLM integration
- Multi-turn attacks
- Self-play evaluation

---

## Trust Boundaries and Untrusted Contexts

A core design principle of this project is that **not all text seen by an LLM should be treated as instructions**.

Modern agentic systems ingest content from multiple sources, including:
- user input
- retrieved documents (RAG)
- tool outputs
- system-level instructions

Only system-level instructions are trusted. All other content is treated as **untrusted data**, even if it appears instruction-like.

### Explicit message schema

Each piece of context is represented as a structured message segment with:
- a `source` (system, user, tool_output, retrieved_doc)
- a `trust_level` (trusted or untrusted)
- the raw `content`

This prevents loss of provenance during prompt assembly and enables precise attribution during evaluation.

### Non-flattening prompt assembly

Rather than concatenating strings, the agent assembles prompts from typed message segments.  
Trust metadata is preserved end-to-end and logged for every run.

### Delimited prompt rendering

Before execution, the final prompt is rendered with explicit trust delimiters:

BEGIN_SYSTEM
...
END_SYSTEM

BEGIN_UNTRUSTED_USER
...
END_UNTRUSTED_USER

BEGIN_UNTRUSTED_TOOL_OUTPUT
...
END_UNTRUSTED_TOOL_OUTPUT


These delimiters make trust boundaries explicit to both the model and the surrounding runtime.  
They form the foundation for detecting and preventing prompt injection, where untrusted content attempts to override system intent.

This design treats prompt injection as a **control-flow integrity problem** rather than a string-matching problem.







## Key idea

Prompt injection is not a string-matching problem.
It is a **control-flow integrity problem for natural-language programs**.

This project is an attempt to build the infrastructure needed to reason about that rigorously.
