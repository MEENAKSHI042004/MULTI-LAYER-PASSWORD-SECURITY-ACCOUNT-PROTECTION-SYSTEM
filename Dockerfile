FROM python:3.12-slim

WORKDIR /app

# System deps for bcrypt build (usually not needed with wheels, kept for safety)
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/instance
RUN chmod +x /app/entrypoint.sh

EXPOSE 5000

ENV FLASK_APP=run.py

ENTRYPOINT ["/app/entrypoint.sh"]