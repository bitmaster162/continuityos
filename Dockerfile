FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENV CONTINUITYOS_DB=/data/memory.db
VOLUME ["/data"]
EXPOSE 8077
CMD ["cos", "--db", "/data/memory.db", "api", "--host", "0.0.0.0", "--port", "8077"]
