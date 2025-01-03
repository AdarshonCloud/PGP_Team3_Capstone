# Credit Card and Login Services - Product Contract

## 1. System Overview
An integrated microservices system providing authentication and account management capabilities, with integration points to other team services.

### 1.1 Team Responsibilities
- **Team 3 (Our Team)**: Login Service - Core authentication and account management
- **Other Teams**:
    - Credit Card Service - Credit card operations

### 1.2 Component Architecture
```
[Eureka Server - 8761]
         ↑
         |    
[Login Service - 8081] ←---→ [Credit Card Service - 8083]
         ↓                            ↓
    [MongoDB CCMS]              [MongoDB CCMS]
```

### 1.3 Components Detail
#### 1.3.1 Login Service (Team 3 - Our Service)
- **Port:** 8081
- **Responsibility:** Authentication and account management
- **Features:**
    - User authentication
    - Account verification
    - Password management
    - JWT token generation and validation

#### 1.3.2 Credit Card Service
- **Port:** 8083
- **Dependency Type:** Consumer of Login Service
- **Integration Points:**
    - JWT token validation
    - User authentication status
    - Account verification status

#### 1.3.3 Eureka Server
- **Port:** 8761
- **Configuration:**
  ```properties
  spring.application.name=eureka-server
  server.port=8761
  eureka.client.register-with-eureka=false
  eureka.client.fetch-registry=false
  ```
- **Dependencies:**
  ```xml
  <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-starter-netflix-eureka-server</artifactId>
  </dependency>
  ```

#### 1.3.4 Shared Infrastructure
- **MongoDB Database:** CCMS
- **Service Discovery:** Eureka Server
- **Authentication:** JWT-based system

## 2. Authentication Service API

### 2.1 First-Time Login
- **Endpoint:** POST `/api/customer/login`
- **Purpose:** Initial login for new users
- **Request:**
  ```json
  {
    "email": "string",
    "password": "string"
  }
  ```
- **Success Response (200):**
  ```json
  {
    "message": "Welcome {firstName} {lastName}",
    "token": "string",
    "note": "Account validation status message"
  }
  ```
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 400 | INVALID_REQUEST | Missing fields | `{"error": "Email and password are required"}` |
  | 401 | INVALID_CREDENTIALS | Wrong credentials | `{"error": "Invalid email or password"}` |
  | 403 | ACCOUNT_LOCKED | Account locked | `{"error": "Account is locked. Please reset your password"}` |
  | 403 | UNVERIFIED_ACCOUNT | Not verified | `{"error": "Account not verified. Please verify email"}` |

### 2.2 Subsequent Login
- **Endpoint:** POST `/api/customer/login/subsequent`
- **Purpose:** Regular login for existing users
- **Success Response (200):**
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "name": {
      "first": "John",
      "last": "Doe"
    },
    "accountValidated": true,
    "availableEndpoints": [
      {
        "url": "/api/account",
        "description": "Update personal details and password"
      },
      {
        "url": "/api/creditcards",
        "description": "View all credit cards"
      }
    ]
  }
  ```
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 401 | INVALID_CREDENTIALS | Auth failed | `{"error": "Invalid email or password"}` |
  | 403 | ACCOUNT_LOCKED | Too many attempts | `{"error": "Account locked due to multiple failed attempts"}` |
  | 403 | PASSWORD_EXPIRED | Password expired | `{"error": "Password expired. Please reset"}` |

### 2.3 Send Verification Email
- **Endpoint:** POST `/api/customer/send-verification`
- **Request:**
  ```json
  {
    "email": "string"
  }
  ```
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 400 | INVALID_EMAIL | Invalid format | `{"error": "Invalid email format"}` |
  | 404 | USER_NOT_FOUND | User not found | `{"error": "Customer not found"}` |
  | 409 | ALREADY_VERIFIED | Already verified | `{"error": "Account is already validated"}` |
  | 429 | TOO_MANY_REQUESTS | Recent request | `{"error": "Please wait before requesting again"}` |

### 2.4 Verify Account
- **Endpoint:** GET `/api/customer/verify`
- **Query Params:** token
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 400 | INVALID_TOKEN | Invalid token | `{"error": "Invalid verification token"}` |
  | 400 | TOKEN_EXPIRED | Token expired | `{"error": "Verification token has expired"}` |
  | 404 | TOKEN_NOT_FOUND | Not found | `{"error": "Verification token not found"}` |

### 2.5 Forgot Password Flow
#### Request Reset
- **Endpoint:** POST `/api/customer/forgot-password`
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 400 | INVALID_EMAIL | Invalid format | `{"error": "Invalid email format"}` |
  | 404 | USER_NOT_FOUND | Not found | `{"error": "No account found"}` |
  | 429 | TOO_MANY_REQUESTS | Recent request | `{"error": "Please wait before requesting"}` |

#### Reset Password
- **Endpoint:** POST `/api/customer/forgot-password/reset-password`
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 400 | INVALID_TOKEN | Invalid token | `{"error": "Invalid or expired reset token"}` |
  | 400 | PASSWORD_MISMATCH | No match | `{"error": "Passwords do not match"}` |
  | 400 | WEAK_PASSWORD | Requirements | `{"error": "Password does not meet requirements"}` |

## 3. Credit Card Service API

### 3.1 Add Credit Card
- **Endpoint:** POST `/api/customer/creditcard`
- **Authorization:** Bearer Token
- **Request:**
  ```json
  {
    "cardNumber": "string (16 digits)",
    "cvv": "integer",
    "expiryMonth": "integer",
    "expiryYear": "integer",
    "wireTransactionVendor": "string"
  }
  ```
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 400 | INVALID_CARD | Invalid number | `{"error": "Invalid credit card number"}` |
  | 400 | INVALID_CVV | Invalid CVV | `{"error": "Invalid CVV"}` |
  | 400 | INVALID_EXPIRY | Invalid date | `{"error": "Invalid expiry date"}` |
  | 409 | CARD_EXISTS | Already exists | `{"error": "Credit card already exists"}` |

### 3.2 Get Active Cards
- **Endpoint:** GET `/api/customer/creditcard`
- **Authorization:** Bearer Token
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 401 | UNAUTHORIZED | Invalid token | `{"error": "Invalid or missing token"}` |
  | 403 | TOKEN_EXPIRED | Token expired | `{"error": "Token has expired"}` |
  | 404 | NO_CARDS | None found | `{"error": "No credit cards found"}` |

### 3.3 Delete Card
- **Endpoint:** DELETE `/api/customer/creditcard/{creditCardNumber}`
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 404 | CARD_NOT_FOUND | Not found | `{"error": "Credit card not found"}` |
  | 409 | ALREADY_DELETED | Already deleted | `{"error": "Card already deleted"}` |

### 3.4 Toggle Card Status
- **Endpoint:** PUT `/api/customer/creditcard/{creditCardNumber}/toggle`
- **Error Responses:**
  | Status | Error Code | Description | Response |
  |--------|------------|-------------|-----------|
  | 404 | CARD_NOT_FOUND | Not found | `{"error": "Credit card not found"}` |
  | 409 | CARD_DELETED | Deleted card | `{"error": "Cannot toggle deleted card"}` |

## 4. Security Implementation

### 4.1 Authentication
- JWT-based authentication
- Token validation between services
- Session management
- Password encryption using BCrypt

### 4.2 Data Security
- AES encryption for sensitive data
- Card number masking
- CVV hashing
- HTTPS communication

## 5. Global Error Handling

### 5.1 Standard Error Response
```json
{
  "error": "string",
  "errorCode": "string",
  "timestamp": "string",
  "path": "string",
  "details": "string"
}
```

### 5.2 Common Error Codes
| Code | Description |
|------|-------------|
| INVALID_TOKEN | JWT validation failed |
| SERVER_ERROR | Internal server error |
| DATABASE_ERROR | Database operation failed |
| VALIDATION_ERROR | Request validation failed |
| UNAUTHORIZED | Authentication failed |

### 5.3 Circuit Breaker Errors
| Status | Error Code | Description |
|--------|------------|-------------|
| 503 | SERVICE_UNAVAILABLE | Circuit open |
| 504 | TIMEOUT | Request timeout |

## 6. Data Models

### 6.1 Customer Entity
```json
{
  "username": "johndoe",
  "name": {
    "first": "John",
    "last": "Doe"
  },
  "email": "john.doe@example.com",
  "password": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
  "accountValidated": true,
  "verificationToken": "b9a2ba62-57d6-4149-a45b-9c51ef370f30",
  "resetPasswordToken": null,
  "passwordHistory": [
    "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    "$2a$10$ILGgqXC5YBWNqmEvI8Jyw.u7Zk9W0CZAkPB8KTFhgbBwsLk6Rj02S"
  ]
}
```

### 6.2 Credit Card Entity
```json
{
  "username": "johndoe",
  "creditcards": [
    {
      "creditCardId": 12345,
      "creditCardNumber": "AES256{9cGzKr3+XuVY8zHHVk9kCA==}",
      "expiryMonth": 12,
      "expiryYear": 2025,
      "cvv": 903475928,
      "status": "enabled",
      "deleted": false,
      "wireTransactionVendor": "Visa"
    }
  ]
}
```

## 7. Integration Points

### 7.1 Service Communication Matrix

| From → To          | Login Service | Credit Card Service | Eureka Server |
|-------------------|---------------|-------------------|---------------|
| Login Service     | -             | Token validation  | Registration  |
| Credit Card Service| Auth requests | -                 | Registration  |
| Eureka Server     | Service info  | Service info      | -             |

### 7.2 Team Integration Responsibilities

#### Team 3 (Login Service - Our Team)
- **Provides:**
    - JWT token generation
    - Token validation endpoints
    - Account validation status
    - User authentication status
- **Consumes:**
    - Eureka Server registration

#### Other Teams Dependencies
1. **Credit Card Service**
- **Depends on Login Service for:**
    - Token validation
    - User authentication
    - Account status verification
- **Integration Endpoints:**
  ```
  GET /api/customer/jwt/validate
  POST /api/customer/logout
  ```

2. **Eureka Server**
- **Provides to all services:**
    - Service registration
    - Service discovery
    - Load balancing
- **Configuration Required:**
  ```properties
  eureka.client.service-url.defaultZone=http://localhost:8761/eureka/
  eureka.instance.prefer-ip-address=true
  ```

### 7.3 Shared Resources
1. **MongoDB Database (CCMS)**
- Collection: Customer
- Collection: CreditCard
- Shared connection string format:
  ```
  mongodb+srv://[username]:[password]@ascend.qgdyk.mongodb.net/CCMS
  ```

2. **Email System**
- SMTP Server: smtp.gmail.com
- Port: 587
- Sender: ascendpgp@gmail.com

3. **Service Discovery**
- Eureka Server URL: http://localhost:8761
- Health Check: /actuator/health
- Dashboard: /

## 8. Circuit Breaking Configuration
```yaml
resilience4j.circuitbreaker:
  instances:
    loginService:
      failureRateThreshold: 50
      slidingWindowSize: 5
      waitDurationInOpenState: 10000ms
```

## 9. Monitoring & Logging
- Health check endpoint: `/actuator/health`
- Metrics endpoint: `/actuator/metrics`
- Swagger UI: `/swagger-ui.html`
- Console and file logging
- Optional cloud storage integration
- Optional ELK stack integration