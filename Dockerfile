# Email Security Analyzer — container image
#
# Usage:
#   docker build -t email-security-analyzer .
#   docker run --rm -v "$PWD/samples:/samples" email-security-analyzer analyze /samples/message.eml
#
# Mount any directory containing .eml files to /samples (or another path)
# and pass it as the argument to the `analyze` subcommand.

FROM python:3.12-slim AS base

WORKDIR /app

# Install the package (with the optional dns + whois extras for the fuller
# feature set) without dev/test tooling to keep the image lean.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[dns,whois]"

# Non-root user for defense-in-depth, since this tool handles untrusted
# email content and attachments.
RUN useradd --create-home --shell /usr/sbin/nologin analyzer
USER analyzer

ENTRYPOINT ["email-security-analyzer"]
CMD ["--help"]
