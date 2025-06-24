# Use a Rust base image that includes the necessary toolchain and common build tools.
# 'latest' is convenient for simplicity, but consider pinning a specific version (e.g., rust:1.78-bookworm)
# for better reproducibility in a production environment.
FROM rust:latest

# Install Git to clone your repository.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git cvc4 python3-pip python3-venv curl && \
    rm -rf /var/lib/apt/lists/*

# Create a virtual environment for Python
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Blockchain dependencies
RUN python3 -m pip install argparse requests web3 py-solc-x seaborn scipy matplotlib

# Set the working directory inside the container. This is where your code will live.
WORKDIR /agora

# Clone your Git repository into the container.
# Replace <YOUR_REPO_URL> with the actual URL of your repository.
# For example: https://github.com/rust-lang/rust-by-example.git
# If your repo is private, you'll need to handle authentication (see note below).

RUN git clone https://github.com/ya0guang/agora.git . && \
    rm -rf ./.git # Remove .git directory to prevent credential leaks after clone

# Optional: Build the release version of your application.
# This step compiles your Rust code into an executable.
# The binary will be located in /app/target/release/your_rust_binary_name (replace with your actual binary name).
RUN cargo build

CMD ["bash"]