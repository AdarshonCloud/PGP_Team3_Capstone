FROM maven:3.8.4-openjdk-17 AS build

# Set proxy environment variables with proper escaping
ENV HTTP_PROXY="http://sysproxy.wal-mart.com:8080" \
    HTTPS_PROXY="http://sysproxy.wal-mart.com:8080" \
    http_proxy="http://sysproxy.wal-mart.com:8080" \
    https_proxy="http://sysproxy.wal-mart.com:8080" \
    NO_PROXY="localhost,127.0.0.1,.wal-mart.com"

# Set Maven proxy settings with proper escaping
ENV MAVEN_OPTS="-Dhttp.proxyHost=sysproxy.wal-mart.com \
    -Dhttp.proxyPort=8080 \
    -Dhttps.proxyHost=sysproxy.wal-mart.com \
    -Dhttps.proxyPort=8080 \
    -Dhttp.nonProxyHosts='localhost|127.0.0.1|*.wal-mart.com'"

WORKDIR /app

# Copy Maven configuration
COPY pom.xml .

# Download dependencies separately
RUN mvn dependency:go-offline

# Copy source code
COPY src ./src

# Build application
RUN mvn clean package -DskipTests

# Create runtime image using Eclipse Temurin instead of OpenJDK
FROM eclipse-temurin:17-jdk-jammy

# Set the same proxy environment variables in the runtime image
ENV HTTP_PROXY="http://sysproxy.wal-mart.com:8080" \
    HTTPS_PROXY="http://sysproxy.wal-mart.com:8080" \
    http_proxy="http://sysproxy.wal-mart.com:8080" \
    https_proxy="http://sysproxy.wal-mart.com:8080" \
    NO_PROXY="localhost,127.0.0.1,.wal-mart.com"

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