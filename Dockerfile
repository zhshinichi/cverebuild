# Use an official Python runtime as a parent image
FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \ 
	docker.io \
	python3 \ 
	python3-pip \
	curl \
	tree \
	wget \
	zip \
	git \
	xvfb

RUN curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x /usr/local/bin/docker-compose

COPY ./src /src
WORKDIR /src/agentlib
RUN pip3 install selenium
RUN pip3 install -e .

# Install Playwright and its browser dependencies
# This pre-installs Playwright to avoid Agent getting stuck trying to install system libs
RUN pip3 install playwright && \
    playwright install-deps chromium && \
    playwright install chromium

# Pre-install other commonly needed security testing tools
RUN pip3 install \
    requests \
    beautifulsoup4 \
    lxml \
    pyyaml \
    httpx \
    aiohttp

# Install professional security testing tools
RUN apt-get update && apt-get install -y \
    nmap \
    nikto \
    && rm -rf /var/lib/apt/lists/*

# Install Python-based security tools
RUN pip3 install \
    sqlmap \
    semgrep

# Install Commix (Command Injection Exploiter)
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix && \
    ln -s /opt/commix/commix.py /usr/local/bin/commix && \
    chmod +x /opt/commix/commix.py

# Install XSStrike (XSS Scanner)
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike && \
    pip3 install -r /opt/xsstrike/requirements.txt && \
    ln -s /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /opt/xsstrike/xsstrike.py

# Install Nuclei (Template-based vulnerability scanner)
# LLM generates YAML templates which Nuclei executes - more reliable than raw Python PoC
RUN cd /tmp && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    unzip -o nuclei_3.3.7_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -f nuclei_3.3.7_linux_amd64.zip LICENSE.md README*.md
