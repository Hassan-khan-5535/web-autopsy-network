FROM mcr.microsoft.com/playwright/python:v1.50.0-noble

WORKDIR /app

COPY requirements.txt ./
RUN pip install --default-timeout=1000 --no-cache-dir -r requirements.txt

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

COPY --chown=appuser:appgroup . .

USER appuser

EXPOSE 8001

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
