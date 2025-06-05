FROM python:3.10-slim
RUN adduser --no-create-home --disabled-login appuser
WORKDIR /app
COPY requirements.txt .
COPY init.sql /app/init.sql
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER appuser
CMD sh -c "gunicorn --bind :$PORT --workers 1 --threads 8 main:app"