FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
EXPOSE 8080
ENV PYTHONUNBUFFERED=1
ENV THREATLINE_HOST=0.0.0.0
ENV THREATLINE_PORT=8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('THREATLINE_PORT', '8080') + '/healthz', timeout=2).read()"]
CMD ["python", "-m", "threatline"]
