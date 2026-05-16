.PHONY: install test lint format eval calibrate ablation report all clean

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

# ── Evaluation pipeline ───────────────────────────────────────────────────────

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

# Run everything (install + test + eval)
all: install test eval

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f data/calibration_report.json data/ablation_report.json data/report.html
