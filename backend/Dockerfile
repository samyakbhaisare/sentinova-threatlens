FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Apply base-image security updates; unfixed Debian advisories are reported by
# the image scan but cannot be resolved from this Dockerfile.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools && pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home app
COPY . .
RUN mkdir -p /data/reports && chown -R app:app /app /data
USER app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
