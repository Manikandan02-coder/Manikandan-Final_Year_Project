FROM python:3.9

WORKDIR /app

# libpcap-dev needed for raw packet capture on Linux
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy cryptography

RUN mkdir -p /app/data1

COPY capturefinal.py .

CMD ["python", "capturefinal.py"]