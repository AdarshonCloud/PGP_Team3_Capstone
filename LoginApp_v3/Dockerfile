FROM maven:3.8.4-openjdk-17 AS build

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
