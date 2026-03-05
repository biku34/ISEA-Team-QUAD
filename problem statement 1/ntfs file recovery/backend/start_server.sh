#!/bin/bash
# Start the FastAPI server with increased limits for large E01 file uploads

# Kill any existing uvicorn processes
pkill -f "uvicorn app.main:app"

# Start uvicorn with custom settings for large file uploads
# --limit-max-requests: Maximum number of requests before worker restart
# --timeout-keep-alive: Keep alive timeout
# --limit-concurrency: Max concurrent connections
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --timeout-keep-alive 300 \
  --limit-concurrency 100 \
  --log-level info
