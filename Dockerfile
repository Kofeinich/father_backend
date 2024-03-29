FROM python:3.8
WORKDIR /app
ADD requirements.txt .
RUN pip install -r requirements.txt
ADD . .
CMD ["python", "-m", "uvicorn",  "main:app", "--host", "0.0.0.0"]