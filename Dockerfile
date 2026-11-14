FROM python:3.12-slim

WORKDIR /app

# Only what the API needs (no dashboard, no tests)
RUN pip install --no-cache-dir pandas fastapi uvicorn

COPY src ./src

# Create the simulated logs, run the detection and fill the database at build time
RUN python src/generate_logs.py && python src/severity.py

# Run as a normal user, not as root
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "api:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8000"]
