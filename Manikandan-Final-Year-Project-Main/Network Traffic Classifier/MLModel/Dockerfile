FROM python:3.9

WORKDIR /app

RUN pip install --no-cache-dir \
    numpy==1.23.5 \
    pandas \
    cryptography \
    scikit-learn==1.2.2 \
    scapy

RUN mkdir -p /app/data2 /app/data3

COPY deploydocker.py .
COPY alert.py .
COPY RFCMODEL.pkl .
COPY scaler.sc .

CMD ["python", "deploydocker.py"]