FROM python:3.9

WORKDIR /app

# Pin numpy to version compatible with scikit-learn==1.2.2
RUN pip install --no-cache-dir \
    numpy==1.23.5 \
    pandas \
    cryptography \
    scikit-learn==1.2.2

# Copy all required files
COPY AnomalyDetector.py .
COPY isolationforest.pkl isolationforestv2.pkl
COPY scaler.pkl scalerv2.pkl
COPY alert.py .

# Create required directories
RUN mkdir -p /app/data2 /app/data3

CMD ["python", "AnomalyDetector.py"]