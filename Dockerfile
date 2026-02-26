FROM python:3.12-slim

# Don't buffer stdout/stderr — keeps logs visible in real time
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (separate layer so rebuilds are fast when only code changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py ad.py ./
COPY templates/ templates/

# Run as a non-root user
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE ${PORT:-5000}

# Gunicorn: 2 worker processes, bind to the port set by $PORT (default 5000).
# Adjust --workers based on the host's CPU count (2-4 * num_cores is typical).
CMD gunicorn --workers 2 --worker-tmp-dir /dev/shm --bind "0.0.0.0:${PORT:-5000}" app:app
