# Since the server relies on Hail as well, we're reusing the driver image.
ARG DRIVER_IMAGE
FROM ${DRIVER_IMAGE}

RUN pip install \
    google-api-python-client==2.10.0 \
    google-cloud-secret-manager==2.2.0 \
    google-cloud-pubsub==2.3.0 \
    google-cloud-logging==3.1.1 \
    gunicorn \
    protobuf==3.20.1

ARG DRIVER_IMAGE
ENV DRIVER_IMAGE $DRIVER_IMAGE

# Allow statements and log messages to immediately appear in the Knative logs.
ENV PYTHONUNBUFFERED 1

ENV PORT 8080
EXPOSE $PORT

COPY main.py cromwell.py util.py ./

# Prepare the Hail deploy config to point to the CPG domain.
COPY deploy-config.json /deploy-config/deploy-config.json

CMD gunicorn --bind :$PORT --worker-class aiohttp.GunicornWebWorker main:init_func
