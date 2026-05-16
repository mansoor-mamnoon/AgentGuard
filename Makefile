.PHONY: install test test-integration lint format eval calibrate ablation report all clean \
        benchmarks bench demo baselines gate-ablation adaptive-redteam \
        mcp-demo mcp-proxy

# ── Setup ─────────────────────────────────────────────────────────────────────

install:
	uv sync

# ── Tests ─────────────────────────────────────────────────────────────────────

test:
	uv run pytest -q

# ── Linting / formatting ──────────────────────────────────────────────────────

lint:
	uv run ruff check .
	uv run black . --check

format:
	uv run ruff format .
	uv run black .

# ── Benchmark suite (Parts 1 & 8) ────────────────────────────────────────────

# Generate all 4 200 benchmark cases
benchmarks:
	uv run python -m benchmarks.generate
	@echo "Generated benchmarks/agentdojo/benign.jsonl (1 000)"
	@echo "Generated benchmarks/agentdojo/direct_attacks.jsonl (1 000)"
	@echo "Generated benchmarks/custom_enterprise_rag/indirect_attacks.jsonl (1 000)"
	@echo "Generated benchmarks/tool_exfiltration/attacks.jsonl (500)"
	@echo "Generated benchmarks/multi_turn/attacks.jsonl (500)"
	@echo "Generated benchmarks/benign_hard_negatives/negatives.jsonl (200)"

# Run benchmark evaluation across all five families
bench-suite:
	uv run python -m benchmarks.run_benchmarks

# Baseline comparison (Part 8)
baselines:
	uv run python -m eval.baselines --json data/baseline_results.json

# Tool-gate ablation (Part 3)
gate-ablation:
	uv run python -m eval.eval_tool_gating

# Adaptive red-team (Part 6)
adaptive-redteam:
	uv run python -m eval.adaptive_redteam

# ── Latency benchmarks (Part 9) ───────────────────────────────────────────────

bench:
	uv run python -m bench.bench_latency
	uv run python -m bench.bench_cache

bench-throughput:
	uv run python -m bench.bench_throughput --n 500 --workers 4

# ── Demo (Part 10) ────────────────────────────────────────────────────────────

demo:
	uv run python -m demo.run_demo --scenario 0

demo-all:
	uv run python -m demo.run_demo --all

# ── MCP Security Proxy ────────────────────────────────────────────────────────

mcp-demo:
	uv run python -m demo.mcp_proxy_demo

# Run the real MCP proxy (requires --upstream arg)
# Example: make mcp-proxy UPSTREAM="python -m integration.servers.filesystem_server ./sandbox"
mcp-proxy:
	uv run python -m mcp_proxy --upstream "$(UPSTREAM)" $(PROXY_FLAGS)

# Integration tests (real proxy + real servers)
test-integration:
	uv run pytest -q integration/

# ── Legacy evaluation pipeline ────────────────────────────────────────────────

# Step 1: calibrate thresholds against the validation set
calibrate:
	uv run python -m eval.calibrate_thresholds \
		--dataset data/attacks_seed.jsonl \
		--benign  data/benign.jsonl \
		--output  data/calibration_report.json \
		--fpr_budget 0.15

# Step 2: run ablation study (all six configurations)
ablation:
	uv run python -m eval.run_ablation \
		--attacks data/attacks_v2.jsonl \
		--output  data/ablation_report.json \
		--limit   50

# Step 3: generate HTML dashboard
report:
	uv run python -m eval.run_report \
		--calibration data/calibration_report.json \
		--output data/report.html

# Run the full eval pipeline end-to-end
eval: calibrate ablation report
	@echo ""
	@echo "=== Eval complete ==="
	@echo "  Calibration : data/calibration_report.json"
	@echo "  Ablation    : data/ablation_report.json"
	@echo "  Report      : data/report.html"

# Run everything (install + test + benchmarks + eval)
all: install test benchmarks bench-suite eval

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f data/calibration_report.json data/ablation_report.json data/report.html data/baseline_results.json
