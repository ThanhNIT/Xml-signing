FROM eclipse-temurin:17-jdk-alpine
VOLUME /tmp
ARG JAR_FILE
ARG FILE_PATH
COPY ${JAR_FILE} /app/app.jar
# Copy the file specified by the build argument into the Docker image
COPY $FILE_PATH /app/yourfile

# Set the working directory
WORKDIR /app
ENTRYPOINT ["java","-jar","/app.jar"]