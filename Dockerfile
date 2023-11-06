FROM openjdk:8-jdk-alpine
VOLUME /tmp
COPY /target/kz-0.0.1-SNAPSHOT.jar /app/app.jar
# Copy the file specified by the build argument into the Docker image
COPY /src/main/resources/keys/key.p12 /app/key.p12

# Set the working directory
WORKDIR /app
ENTRYPOINT ["java","-jar","app.jar"]