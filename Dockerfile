FROM ubuntu:18.04
COPY . /app
WORKDIR /app
RUN ./gradlew test