FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY provisioner.py .

# Create directories for volumes
RUN mkdir -p /app/certs /app/data

EXPOSE 5000

CMD ["python", "provisioner.py"]