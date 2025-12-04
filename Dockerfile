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
