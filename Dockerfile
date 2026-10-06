FROM python:3.11.9-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN addgroup --system app && adduser --system --ingroup app app
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip==24.3.1 && pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN chown -R app:app /srv
USER app
WORKDIR /srv/app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
