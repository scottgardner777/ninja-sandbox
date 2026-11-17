# One image for the API (+ UI) and the sensor; the service `command` picks the role.
# The API drives sibling containers (sinkhole, holder, runner) through the Docker socket, so the docker CLI is here.
FROM python:3.12-alpine
RUN apk add --no-cache docker-cli bash
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sandbox ./sandbox
COPY ui ./ui
COPY cell ./cell
ENV SANDBOX_DATA=/data PYTHONUNBUFFERED=1
EXPOSE 8800
CMD ["uvicorn", "sandbox.api:app", "--host", "0.0.0.0", "--port", "8800"]
