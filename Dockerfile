# Shakedown, live-capable. Credentials are never baked in: pass NEBIUS_API_KEY, NEBIUS_PROJECT_ID and TAVILY_API_KEY
# as environment variables at run time. The datasets are fetched at build time from pinned, hash-verified sources
# (tools/fetch_data.py) and are not part of the repository. The evaluation image must already exist in the Nebius
# project (python tools/build_sandbox_image.py, run once).
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv==0.11.*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY . .
# Datasets: SigmaHQ at the pinned commit (sparse) and evtx-baseline v0.8.5. About 1.1 GB on disk; the archives are
# removed once extracted.
RUN uv run python tools/fetch_data.py && rm -f data/raw/evtx-baseline/v0.8.5/*.tgz

RUN useradd --create-home --uid 10001 shakedown && mkdir /state && chown -R shakedown /state
USER shakedown
VOLUME ["/state"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=4)"

# Defaults for a public, bounded live demo. Override on the command line to change a cap.
# Add --trust-proxy only if a reverse proxy you control sets X-Forwarded-For; without it every visitor behind the
# proxy shares one cooldown (safe for cost, slow for judges). With it and no proxy, the cooldown can be spoofed.
ENV PATH="/app/.venv/bin:$PATH"
CMD ["python", "-m", "shakedown.serve", "--live", "--host", "0.0.0.0", "--port", "8000", \
     "--budget-file", "/state/budget.json", "--daily-cap", "30", "--total-cap", "400", \
     "--cooldown", "90", "--max-concurrent", "3"]
