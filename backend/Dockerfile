FROM python:3.11-slim

WORKDIR /app

# Install system dependencies required for analysis tools and weasyprint
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Create directories for uploads and reports
RUN mkdir -p /data/uploads /data/reports /data/trained_models

# Copy application code
COPY . .

# Create templates directory
RUN mkdir -p templates

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UPLOAD_DIR=/data/uploads
ENV REPORTS_DIR=/data/reports
ENV MODEL_PATH=/data/trained_models/trained.pkl

# Expose port
EXPOSE 8000

# Set non-root user for security
RUN adduser --disabled-password --gecos "" appuser
RUN chown -R appuser:appuser /app /data
USER appuser

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]