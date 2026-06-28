# mcp-gateway — a security proxy in front of an MCP server.
#   make help     # list targets
PORT ?= 8080

.PHONY: help up serve demo test audit down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'

up: ## Create the venv and install the gateway (uv sync)
	uv sync

serve: up ## Run the gateway (FastAPI/uvicorn) -> http://127.0.0.1:$(PORT)/mcp
	uv run uvicorn mcp_gateway.app:create_app --factory --host 127.0.0.1 --port $(PORT)

demo: up ## Offline before/after story: four MCP attacks, without vs through the gateway
	uv run python scripts/demo.py

test: up ## Run the test suite
	uv run pytest -q

audit: ## Pretty-print the audit log (one decision per line)
	@test -f audit.jsonl && cat audit.jsonl || echo "no audit.jsonl yet — run 'make demo' or send a request"

down: ## Remove the venv, caches and local audit log
	rm -rf .venv .pytest_cache .ruff_cache audit.jsonl
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
