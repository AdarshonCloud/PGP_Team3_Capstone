                               # Customer Login Service

## Overview
Authentication and account management microservice for the Ascend PGP Batch 2 project. This service is part of a larger microservices architecture, developed by Team 3.

## Team Structure and Services
- **Team 3 (Our Team)**: Login Service (Port: 8081)
- **Team 2**: Credit Card Service (Port: 8083)

## Prerequisites
- Java 17
- Maven 3.x
- MongoDB
- Docker (optional)
- SMTP Server access

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/AdarshonCloud/PGP_Team3_Capstone.git
cd customerlogin
```

### 2. Configure Application Properties
Create/update `src/main/resources/application.properties`:
```properties
# Application
spring.application.name=customerlogin
server.port=8081

# MongoDB
spring.data.mongodb.uri=mongodb+srv://[username]:[password]@ascend.qgdyk.mongodb.net/CCMS
spring.data.mongodb.database=CCMS

# JWT Configuration
jwt.secret=your_jwt_secret
jwt.expiration=3600000

# Eureka Client
eureka.client.service-url.defaultZone=http://localhost:8761/eureka/
eureka.instance.prefer-ip-address=true

# Email Configuration
spring.mail.host=smtp-gw1.wal-mart.com
spring.mail.port=25
sender.email=Teams3_PGP@walmart.com

# Circuit Breaker
resilience4j.circuitbreaker.instances.loginService.failure-rate-threshold=50
resilience4j.circuitbreaker.instances.loginService.sliding-window-size=5
```

### 3. Build and Run
```bash
# Build the project
mvn clean install

# Run the application
mvn spring-boot:run
```

### 4. Verify Installation
- Service Health: http://localhost:8081/actuator/health
- Swagger UI: http://localhost:8081/swagger-ui.html
- Eureka Dashboard: http://localhost:8761

## Key Features

### 1. Authentication
- First-time login
- Subsequent login
- JWT token generation
- Token validation

### 2. Account Management
- Email verification
- Password reset
- Change password
- Account locking

### 3. Security Features
- Password encryption (BCrypt)
- JWT token authentication
- Account verification flow
- Failed login protection

## API Documentation

### Authentication Endpoints
```
POST /api/customer/login            # First-time login
POST /api/customer/login/subsequent # Regular login
POST /api/customer/logout           # Logout
```

### Account Management Endpoints
```
POST /api/customer/send-verification           # Request verification email
GET  /api/customer/verify                     # Verify account
POST /api/customer/forgot-password            # Request password reset
POST /api/customer/forgot-password/reset      # Reset password
POST /api/customer/change-password            # Change password
```

### JWT Validation Endpoint
```
GET /api/customer/jwt/validate     # Validate JWT token
```

## Integration with Other Services

### 1. Credit Card Service
- **Integration Point**: JWT token validation
- **Endpoint**: GET /api/customer/jwt/validate
- **Authentication**: None (internal service call)
```json
{
    "username": "user123",
    "email": "user@example.com"
}
```

### 2. Eureka Server
- **Purpose**: Service discovery
- **Configuration Required**:
```properties
eureka.client.service-url.defaultZone=http://localhost:8761/eureka/
eureka.instance.prefer-ip-address=true
```

## Database Schema

### Customer Collection
```json
{
  "username": "string",
  "name": {
    "first": "string",
    "last": "string"
  },
  "email": "string",
  "password": "string (encrypted)",
  "accountValidated": "boolean",
  "verificationToken": "string",
  "resetPasswordToken": "string",
  "passwordHistory": ["string"]
}
```

## Testing
```bash
# Run unit tests
mvn test

# Run integration tests
mvn verify
```

## Monitoring

### Available Endpoints
- Health: /actuator/health
- Metrics: /actuator/metrics
- Swagger UI: /swagger-ui.html

### Logging
Logs are written to:
```
/Users/a0s0nmi/IdeaProjects/Apps_v3/Logs/LoginLogs/
```

## Circuit Breaker
The service uses Resilience4j for circuit breaking:
```yaml
resilience4j.circuitbreaker:
  instances:
    loginService:
      failureRateThreshold: 50
      slidingWindowSize: 5
      waitDurationInOpenState: 10000ms
```

## Error Handling
Standard error response format:
```json
{
  "error": "Error message",
  "errorCode": "ERROR_CODE",
  "timestamp": "2024-01-02T12:00:00Z",
  "path": "/api/path"
}
```

## Contributing
1. Fork the repository
2. Create a feature branch
3. Submit pull request