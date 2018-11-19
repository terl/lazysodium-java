FROM gradle:alpine
COPY . /app
WORKDIR /app
RUN ./gradlew test