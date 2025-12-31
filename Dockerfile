FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt update && apt upgrade -y && apt install -y \
    net-tools \
    iproute2 \
    iputils-ping \
    curl \
    nmap \
    nano \
    vim \
    dnsutils \
    git \
    python3 \
    python3-pip \
    wget \
    unzip \
    p7zip-full \
    file \
    && apt clean

# Create workspace directory structure in /opt/workspace (will be copied to mounted /workspace on startup)
RUN mkdir -p /opt/workspace/tools/capa /opt/workspace/tools/floss

# Download and install CAPA v9.3.1
RUN cd /tmp && \
    wget -q https://github.com/mandiant/capa/releases/download/v9.3.1/capa-v9.3.1-linux.zip && \
    unzip -q capa-v9.3.1-linux.zip -d /opt/workspace/tools/capa && \
    chmod +x /opt/workspace/tools/capa/capa && \
    rm -f capa-v9.3.1-linux.zip

# Download and install FLOSS v3.1.1
RUN cd /tmp && \
    wget -q https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip && \
    unzip -q floss-v3.1.1-linux.zip -d /opt/workspace/tools/floss && \
    chmod +x /opt/workspace/tools/floss/floss && \
    rm -f floss-v3.1.1-linux.zip

# Clone theZoo malware samples repository
RUN cd /opt/workspace && \
    git clone https://github.com/ytisf/theZoo.git

# Add capa and floss to PATH in ~/.bashrc
RUN echo '' >> ~/.bashrc && \
    echo '# Malware analysis tools' >> ~/.bashrc && \
    echo 'export PATH="/workspace/tools/capa:/workspace/tools/floss:$PATH"' >> ~/.bashrc

# Set working directory
WORKDIR /workspace

# Copy Python tool files to a build location (will be copied to mounted /workspace on startup)
COPY Agent-Zero.py /opt/workspace/
COPY agent-zero2.0.py /opt/workspace/
COPY requirements.txt /opt/workspace/
COPY env /opt/workspace/.env

# Install Python dependencies
# Using --break-system-packages is acceptable in Docker containers
RUN pip3 install --no-cache-dir --break-system-packages -r /opt/workspace/requirements.txt

# Create entrypoint script to copy built files to mounted workspace
RUN echo '#!/bin/bash' > /entrypoint.sh && \
    echo '# Copy built files to mounted workspace on startup' >> /entrypoint.sh && \
    echo 'echo "Initializing workspace..."' >> /entrypoint.sh && \
    echo 'if [ ! -f /workspace/Agent-Zero.py ]; then' >> /entrypoint.sh && \
    echo '    echo "Copying Python tools to /workspace..."' >> /entrypoint.sh && \
    echo '    cp /opt/workspace/Agent-Zero.py /workspace/ 2>/dev/null || true' >> /entrypoint.sh && \
    echo '    cp /opt/workspace/agent-zero2.0.py /workspace/ 2>/dev/null || true' >> /entrypoint.sh && \
    echo '    cp /opt/workspace/requirements.txt /workspace/ 2>/dev/null || true' >> /entrypoint.sh && \
    echo '    # Copy .env and strip carriage returns (Windows line endings)' >> /entrypoint.sh && \
    echo '    if [ -f /opt/workspace/.env ]; then' >> /entrypoint.sh && \
    echo '        sed "s/\r$//" /opt/workspace/.env > /workspace/.env' >> /entrypoint.sh && \
    echo '    fi' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'if [ ! -d /workspace/tools ]; then' >> /entrypoint.sh && \
    echo '    echo "Copying analysis tools to /workspace..."' >> /entrypoint.sh && \
    echo '    mkdir -p /workspace/tools' >> /entrypoint.sh && \
    echo '    cp -r /opt/workspace/tools/* /workspace/tools/ 2>/dev/null || true' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'if [ ! -d /workspace/theZoo ]; then' >> /entrypoint.sh && \
    echo '    echo "Copying theZoo samples to /workspace..."' >> /entrypoint.sh && \
    echo '    cp -r /opt/workspace/theZoo /workspace/ 2>/dev/null || true' >> /entrypoint.sh && \
    echo 'fi' >> /entrypoint.sh && \
    echo 'exec "$@"' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Load environment variables from .env file
# Note: Docker will handle this via docker-compose, but we can also source it
# This ensures env vars are available even when accessing container directly
# Strip carriage returns when loading to handle Windows line endings
RUN echo '' >> ~/.bashrc && \
    echo '# Load environment variables' >> ~/.bashrc && \
    echo 'if [ -f /workspace/.env ]; then' >> ~/.bashrc && \
    echo '    export $(grep -v "^#" /workspace/.env | grep -v "^$" | sed "s/\r$//" | xargs)' >> ~/.bashrc && \
    echo 'fi' >> ~/.bashrc

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Set default command to bash to keep container running
# Users can run the tool manually with: python3 /workspace/agent-zero2.0.py
# Or auto-start it by overriding CMD: docker run ... static python3 /workspace/agent-zero2.0.py
CMD ["/bin/bash"]


