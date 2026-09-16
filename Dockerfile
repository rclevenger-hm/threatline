FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
EXPOSE 8080
ENV THREATLINE_HOST=0.0.0.0
ENV THREATLINE_PORT=8080
CMD ["python", "-m", "threatline"]
