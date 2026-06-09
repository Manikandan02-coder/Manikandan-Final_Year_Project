FROM python:3.9

WORKDIR /app

RUN pip install --no-cache-dir pandas scapy cryptography

RUN mkdir -p /app/data1 /app/data2

# Was copying to /app1 but WORKDIR is /app — fixed
COPY extractfinal.py .

CMD ["python", "extractfinal.py"]