FROM python:3.12-slim

WORKDIR /app

# Install the package with the web extra. Copy metadata first for layer caching.
COPY pyproject.toml requirements.txt README.md ./
COPY config ./config
COPY src ./src
RUN pip install --no-cache-dir -e ".[web]"

# Run the pipeline and bake a static dashboard into the image at build time.
# It runs offline against the bundled fixtures, so the build needs no network.
RUN threatint-static --offline --out /app/dist/index.html

ENV THREATINT_CONFIG=/app/config/config.yaml
EXPOSE 12000

# Default: serve the live Flask dashboard. The baked /app/dist/index.html is
# also available for static hosting (e.g. GitHub Pages).
CMD ["threatint-web", "--offline", "--host", "0.0.0.0", "--port", "12000"]
