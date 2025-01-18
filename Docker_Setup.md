# Customer Login Service - Docker Setup Documentation

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Project Structure](#project-structure)
3. [Corporate Proxy Configuration](#corporate-proxy-configuration)
4. [Docker Configuration](#docker-configuration)
5. [CORS Configuration](#cors-configuration)
6. [Build and Run Instructions](#build-and-run-instructions)
7. [Environment Variables](#environment-variables)
8. [Troubleshooting](#troubleshooting)

## Prerequisites
- Docker Desktop installed
- Java 17
- Maven
- Access to corporate proxy (configured in Docker Desktop)
- MongoDB Atlas access (for production)

## Project Structure
```
CustomerLogin/
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── ascendpgp/
│                   └── customerlogin/
│                       └── config/
│                           └── WebConfig.java
├── Dockerfile
├── docker-compose.yml
├── application.properties
├── application-docker.properties
└── pom.xml
```

## Corporate Proxy Configuration

### Docker Desktop Proxy Settings
1. Open Docker Desktop
2. Go to Settings → Resources → Proxies
3. Select "Manual proxy configuration"
4. Configure:
   ```
   Web Server (HTTP): http://sysproxy.wal-mart.com:8080
   Secure Web Server (HTTPS): http://sysproxy.wal-mart.com:8080
   Bypass for these hosts & domains: localhost,127.0.0.1
   ```

### Dockerfile Proxy Configuration
```dockerfile
# Build stage
FROM maven:3.8.4-openjdk-17-slim AS build

# Set proxy settings for Maven
ENV MAVEN_OPTS="-Dhttp.proxyHost=sysproxy.wal-mart.com \
    -Dhttp.proxyPort=8080 \
    -Dhttps.proxyHost=sysproxy.wal-mart.com \
    -Dhttps.proxyPort=8080 \
    -Dhttp.nonProxyHosts=localhost|127.0.0.1"

# Rest of Dockerfile...
```

### Docker Compose Proxy Settings
```yaml
version: '3.8'
services:
  customerlogin-app:
    build:
      context: .
      network: host
    environment:
      - HTTP_PROXY=http://sysproxy.wal-mart.com:8080
      - HTTPS_PROXY=http://sysproxy.wal-mart.com:8080
      - NO_PROXY=localhost,127.0.0.1,mongodb+srv
    # Rest of configuration...
```

## CORS Configuration

### WebConfig.java
```java
package com.ascendpgp.customerlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                    .allowedOriginPatterns("*")
                    .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                    .allowedHeaders("*")
                    .allowCredentials(true);
            }
        };
    }
}
```

## Docker Configuration

### Dockerfile
```dockerfile
# Build stage
FROM maven:3.8.4-openjdk-17-slim AS build

# Maven proxy settings
ENV MAVEN_OPTS="-Dhttp.proxyHost=sysproxy.wal-mart.com -Dhttp.proxyPort=8080 -Dhttps.proxyHost=sysproxy.wal-mart.com -Dhttps.proxyPort=8080"

WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# Run stage
FROM openjdk:17-jdk-slim
WORKDIR /app

# Create logs directory and set permissions
RUN mkdir -p /app/logs && \
    addgroup --system --gid 1001 appuser && \
    adduser --system --uid 1001 --ingroup appuser appuser && \
    chown -R appuser:appuser /app

COPY --from=build /app/target/*.jar app.jar

USER appuser

EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  customerlogin-app:
    build:
      context: .
      network: host
    platform: linux/arm64
    ports:
      - "8081:8081"
    environment:
      - SPRING_DATA_MONGODB_URI=mongodb+srv://[username]:[password]@[host]/[database]
      - SPRING_DATA_MONGODB_DATABASE=CCMS
      - EUREKA_CLIENT_ENABLED=false
      - SPRING_CLOUD_DISCOVERY_ENABLED=false
      - HTTP_PROXY=http://sysproxy.wal-mart.com:8080
      - HTTPS_PROXY=http://sysproxy.wal-mart.com:8080
      - NO_PROXY=localhost,127.0.0.1,mongodb+srv
    volumes:
      - ./logs:/app/logs
    dns:
      - 8.8.8.8
      - 8.8.4.4

## Build and Run Instructions

1. Configure Docker Desktop proxy settings as described above

2. Build the Docker image:
```bash
docker-compose build --no-cache
```

3. Run the container:
```bash
docker-compose up
```

4. Verify the application is running:
```bash
curl http://localhost:8081/actuator/health
```

## Environment Variables
| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| SPRING_DATA_MONGODB_URI | MongoDB connection string | Yes | - |
| SPRING_DATA_MONGODB_DATABASE | Database name | Yes | CCMS |
| HTTP_PROXY | Corporate proxy URL | Yes | http://sysproxy.wal-mart.com:8080 |
| HTTPS_PROXY | Corporate proxy URL | Yes | http://sysproxy.wal-mart.com:8080 |
| NO_PROXY | Proxy bypass list | No | localhost,127.0.0.1 |

## Troubleshooting

### Common Issues and Solutions

1. **Proxy Connection Issues**
   - Ensure Docker Desktop proxy settings are configured correctly
   - Verify corporate proxy is accessible
   - Check if proxy settings are being picked up by container:
     ```bash
     docker exec customerlogin-app env | grep -i proxy
     ```

2. **CORS Issues**
   - Verify WebConfig is properly loaded:
     ```bash
     curl -v -H "Origin: http://localhost:3000" http://localhost:8081/actuator/health
     ```
   - Check for CORS headers in response
   - Ensure allowedOriginPatterns is configured correctly

3. **MongoDB Connection Issues**
   - Check MongoDB Atlas IP whitelist
   - Verify connection string
   - Ensure proxy settings allow MongoDB connection
   - Test connection through proxy:
     ```bash
     curl -x http://sysproxy.wal-mart.com:8080 https://[your-mongodb-host]
     ```

### Health Check
The application provides health endpoints:
```bash
curl http://localhost:8081/actuator/health
```

### Logs
Container logs are mounted at `./logs` on the host machine.

To view logs in real-time:
```bash
docker-compose logs -f
```

### Proxy Verification
To verify proxy settings are working:
```bash
# Check environment variables in container
docker exec customerlogin-app env | grep -i proxy

# Test proxy connection from container
docker exec customerlogin-app curl -v --proxy http://sysproxy.wal-mart.com:8080 https://google.com
```
