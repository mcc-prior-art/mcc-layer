FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY main.py /app/main.py
COPY src /app/src
COPY policies /app/policies

ENV MCC_USE_OPA=true
ENV MCC_OPA_URL=http://opa:8181
ENV MCC_OPA_DATA_PATH=mcc/decision
ENV MCC_API_KEY=demo-key

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
