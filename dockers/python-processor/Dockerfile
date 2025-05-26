FROM python:3.12

RUN pip install --upgrade pip && pip install scapy nats-py

RUN pip install --break-system-packages scapy nats-py python-dotenv numpy scipy

WORKDIR /code/python-processor