FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py README.md ./
COPY cybershield ./cybershield
RUN mkdir -p /data && useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app /data
USER appuser
ENV CYBERSHIELD_DB_PATH=/data/cybershield.db
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)" || exit 1
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.headless=true"]
