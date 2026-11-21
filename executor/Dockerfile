FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common ./common
COPY executor ./executor
COPY website_hooks ./website_hooks
EXPOSE 8080
CMD ["uvicorn", "executor.api:app", "--host", "0.0.0.0", "--port", "8080"]
