FROM openjdk:11.0-jre-slim-bullseye

WORKDIR /app
ARG JAR_NAME=uid2-operator
ARG JAR_VERSION=1.0.0
ARG IMAGE_VERSION=1.0.0.unknownhash
ENV JAR_NAME=${JAR_NAME}
ENV JAR_VERSION=${JAR_VERSION}
ENV IMAGE_VERSION=${IMAGE_VERSION}
ENV ENCLAVE_ENVIRONMENT=aws-nitro
ENV UID2_CONFIG_SECRET_KEY="uid2-operator-config-key"

RUN apt update -y \
    && apt install -y pkg-config libssl-dev net-tools curl jq netcat python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install boto3==1.16.9

COPY ./target/${JAR_NAME}-${JAR_VERSION}-jar-with-dependencies.jar /app/${JAR_NAME}-${JAR_VERSION}.jar
COPY ./static /app/static
COPY ./vsockpx /app/
COPY ./libjnsm.so /app/lib/
COPY ./load_config.py /app/
COPY ./make_config.py /app/
COPY ./entrypoint.sh /app/
COPY ./proxies.nitro.yaml /app/
COPY ./conf/default-config.json /app/conf/
COPY ./conf/prod-config.json /app/conf/config.json
COPY ./conf/*.xml /app/conf/

RUN chmod +x /app/vsockpx && chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]
