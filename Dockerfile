FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
RUN useradd -m -u 1000 app && mkdir /data && chown app /data
COPY app/ .
USER app
VOLUME /data
EXPOSE 8000
# 1 Worker + Threads: Prüfungen sind I/O-lastig, Login-Throttling bleibt konsistent
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:8000", "--timeout", "120", "app:app"]
