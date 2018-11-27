FROM gradle:alpine

COPY . /app
WORKDIR /app

RUN gradle test