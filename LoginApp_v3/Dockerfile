FROM --platform=linux/arm64 maven:3.8.4-openjdk-17-slim AS build

# Set proxy environment variables
ENV HTTP_PROXY="http://sysproxy.wal-mart.com:8080" \
    HTTPS_PROXY="http://sysproxy.wal-mart.com:8080" \
    NO_PROXY="localhost,127.0.0.1"

# Set Maven proxy settings
ENV MAVEN_OPTS="-Dhttp.proxyHost=sysproxy.wal-mart.com -Dhttp.proxyPort=8080 -Dhttps.proxyHost=sysproxy.wal-mart.com -Dhttps.proxyPort=8080"

WORKDIR /app

# Copy Maven configuration
COPY pom.xml .

# Copy source code
COPY src ./src

# Build application
RUN mvn clean package -DskipTests

# Create runtime image
FROM --platform=linux/arm64 openjdk:17-jdk-slim

WORKDIR /app

# Create logs directory and set permissions
RUN mkdir -p /app/logs && \
    groupadd -r appuser && \
    useradd -r -g appuser appuser && \
    chown -R appuser:appuser /app

# Copy jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Set user
USER appuser

# Expose port
EXPOSE 8081

# Start application
ENTRYPOINT ["java", "-jar", "app.jar"]
