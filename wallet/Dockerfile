FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Default port for the demo (matches scripts that use :3000)
ENV PORT=3000

CMD ["sh", "-lc", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]