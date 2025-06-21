FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and security updates
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Use the PORT environment variable or default to 5000
EXPOSE ${PORT:-5000}

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Use Gunicorn with the config file
CMD gunicorn -c gunicorn.conf.py main:app
