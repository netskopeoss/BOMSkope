#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Print debug information
echo "Starting entrypoint script..."

# Run the initialization script
echo "Running init.py to initialize the database..."
make

# Run the initialization script
echo "Installing the Gunicorn library..."
venv/bin/pip3 install gunicorn

# Start Nginx in the foreground
echo "Starting Nginx..."
service nginx start
#nginx -g "daemon off;" &

# Start Gunicorn in the foreground
echo "Starting Gunicorn..."
exec /app/venv/bin/gunicorn --group www-data --workers 3 --bind unix:/app/app.sock -m 007 app:app