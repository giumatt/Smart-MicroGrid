# Use a lightweight, up-to-date Python image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install the system dependencies (required for encryption and SQLite)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install the Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code
COPY blockchain.py .

# Copy the source code. Create the folder for the database data
RUN mkdir -p /app/data

CMD ["python", "blockchain.py"]