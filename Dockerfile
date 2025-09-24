# Use Python slim image with SSH client
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set Python unbuffered mode
ENV PYTHONUNBUFFERED=1

# Install SSH client and other system tools
RUN apt-get update && apt-get install -y \
    openssh-client \
    netcat-traditional \
    iputils-ping \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server code
COPY linux_admin_server.py .

# Create non-root user and SSH directory
RUN useradd -m -u 1000 mcpuser && \
    mkdir -p /home/mcpuser/.ssh && \
    chown -R mcpuser:mcpuser /app /home/mcpuser/.ssh

# Create logs directory mount point
RUN mkdir -p /mnt/logs && chown mcpuser:mcpuser /mnt/logs

# Switch to non-root user
USER mcpuser

# Run the server
CMD ["python", "linux_admin_server.py"]