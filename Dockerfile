FROM gradle:latest

COPY . /app
WORKDIR /app

RUN ./gradlew test --info