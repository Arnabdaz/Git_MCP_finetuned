# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS uv

# Install the project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Install the project's dependencies using the lockfile and settings
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev --no-editable

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
ADD . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm

# Create non-root user first
RUN groupadd -r mcpuser && useradd -r -g mcpuser -u 1000 mcpuser

# Install git, security updates, and clean up in single layer
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Copy application files with proper ownership
COPY --from=uv /root/.local /home/mcpuser/.local
COPY --from=uv /app/.venv /app/.venv

# Set correct ownership for application files
RUN chown -R mcpuser:mcpuser /app /home/mcpuser

# Create directory for git operations with proper permissions
RUN mkdir -p /workspace && chown mcpuser:mcpuser /workspace

# Switch to non-root user
USER mcpuser

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:/home/mcpuser/.local/bin:$PATH"
ENV HOME="/home/mcpuser"

# Add security labels
LABEL security.scan="true" \
    security.non-root="true" \
    security.no-new-privileges="true"

# when running the container, add --repository and a bind mount to the host's git repository
ENTRYPOINT ["mcp-server-git"]
