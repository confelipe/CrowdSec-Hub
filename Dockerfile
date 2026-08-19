FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8090

ENV CROWDSEC_DB_PATH=/var/lib/crowdsec/data/crowdsec.db
ENV PROMETHEUS_URL=http://crowdsec:6060/metrics

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
