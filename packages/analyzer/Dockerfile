FROM python:3.11-slim
WORKDIR /app

# System deps needed by androguard
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir ".[dev]" || pip install --no-cache-dir .

# Copy source
COPY src ./src

# Uploads directory — must be mounted to match API container's uploads path
RUN mkdir -p /app/uploads

EXPOSE 5001
ENV ANALYZER_PORT=5001

CMD ["python", "-m", "src.server"]
