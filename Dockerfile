FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates ripgrep ffmpeg \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# GitHub CLI — needed for gh auth, gh pr, gh repo operations
RUN GH_VERSION=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)"/\1/') \
    && curl -fsSL "https://github.com/cli/cli/releases/download/${GH_VERSION}/gh_${GH_VERSION#v}_linux_amd64.tar.gz" | tar xz -C /usr/local/bin --strip-components=1

# Chromium — needed for browser tool
RUN apt-get update && apt-get install -y --no-install-recommends chromium && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

RUN git clone --recurse-submodules https://github.com/NousResearch/hermes-agent.git /opt/hermes-agent

RUN git clone https://github.com/nesquena/hermes-webui.git /opt/hermes-webui

WORKDIR /opt/hermes-agent
RUN uv venv venv --python 3.11 \
    && VIRTUAL_ENV=/opt/hermes-agent/venv uv pip install -e ".[all]"

ENV PATH="/opt/hermes-agent/venv/bin:$PATH"

RUN mkdir -p /root/.hermes/{cron,sessions,logs,memories,skills,pairing,hooks,image_cache,audio_cache} \
    && cp cli-config.yaml.example /root/.hermes/config.yaml \
    && touch /root/.hermes/.env

COPY templates/ /templates/
COPY auth_proxy.py /auth_proxy.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
