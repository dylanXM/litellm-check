FROM ghcr.io/berriai/litellm:main-stable AS proxy
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install litellm
COPY . .
