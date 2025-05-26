# Stage 1: Build gitleaks
FROM golang:1.23-alpine AS gitleaks-builder
RUN apk add --no-cache git
ARG GOPROXY=direct
RUN go install github.com/zricethezav/gitleaks/v8@latest

# Stage 2: Main Image
FROM public.ecr.aws/docker/library/node:lts-bookworm

# Use Bash instead sh
SHELL ["/bin/bash", "-c"]

# Install Python and Dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends apt-transport-https ca-certificates wget curl \
                          gnupg2 software-properties-common less vim jq sudo \
                          xvfb python3-pip python3-dev python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /.venv

# Install binary security tools
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install AWS CDK
RUN npm install -g aws-cdk markdownlint-cli write-good spellchecker-cli 

# Install AWSCLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && bash ./aws/install \
    && rm -rf ./aws

# Copy gitleaks from builder stage
COPY --from=gitleaks-builder /go/bin/gitleaks /usr/local/bin/

ARG USERNAME=vscode
ARG USER_UID=9999
ARG USER_GID=$USER_UID

# # Create a non-root user - see https://aka.ms/vscode-remote/containers/non-root-user.
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd -s /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && mkdir -p /home/$USERNAME/.local/bin \
    && chown -R $USERNAME:$USERNAME /home/$USERNAME/.local \
    && chown -R $USERNAME:$USERNAME /.venv \
    && echo "PATH='/home/$USERNAME/.local/bin:$PATH'" >> home/$USERNAME/.bashrc \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME