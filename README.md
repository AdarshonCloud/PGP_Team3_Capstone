# Customer Login Service
This service provides authentication endpoints for customer login functionality.

## Features
* Initial customer login
* Subsequent login for returning customers
* JWT token-based authentication
* Available API endpoints listing
* Account validation status

## API Endpoints

### 1. Initial Login
```
POST /api/customer/login
Content-Type: application/json

{
    "username": "username",
    "password": "yourpassword"
}
```

**Response:**
```json
{
    "token": "jwt_token_here",
    "firstName": "John",
    "lastName": "Doe",
    "accountValidated": true
}
```

### 2. Subsequent Login
```
POST /api/customer/login/subsequent
Content-Type: application/json

{
    "username": "username_or_email",
    "password": "yourpassword"
}
```

**Response:**
```json
{
    "token": "jwt_token_here",
    "firstName": "John",
    "lastName": "Doe",
    "accountValidated": true,
    "availableEndpoints": [
        {
            "url": "/api/account",
            "description": "Update personal details and password"
        },
        {
            "url": "/api/creditcards",
            "description": "View all credit cards"
        },
        {
            "url": "/api/creditcards/lastmonth",
            "description": "View last month's transactions"
        }
    ]
}
```

### 3. Get Available Endpoints
Retrieve available endpoints for the authenticated user.

```
GET /api/customer/available-endpoints
Authorization: Bearer your_jwt_token_here
```

**Response:**
```json
{
    "username": "example@email.com",
    "availableEndpoints": [
        {
            "url": "/api/account",
            "description": "Update personal details and password"
        },
        {
            "url": "/api/creditcards",
            "description": "View all credit cards"
        },
        {
            "url": "/api/creditcards/lastmonth",
            "description": "View last month's transactions"
        }
    ],
    "userEmail": "youremail"
}
```

## Setup Instructions
1. Ensure MongoDB is running
2. Configure application.properties:
```properties
spring.data.mongodb.uri=mongodb://localhost:27017/creditcard_db
spring.data.mongodb.database=creditcard_db
jwt.secret=your-secret-key
jwt.expiration=3600000
```

3. Run the application:
```bash
mvn spring-boot:run
```

4. Access Swagger UI:
```
http://localhost:8081/swagger-ui.html
```

## Authentication
The service uses JWT tokens for authentication. After successful login:
1. Store the returned JWT token
2. Include it in subsequent requests:
```
Authorization: Bearer your_jwt_token
```

## Error Handling
Common error responses:
* 400: Invalid credentials or validation errors
* 401: Unauthorized access or invalid token
* 403: Account not verified

Example error response:
```json
{
    "message": "Invalid username or password.",
    "errorCode": "AUTH_ERROR",
    "timestamp": 1733339421147
}
```

## Testing with cURL
Here are example cURL commands for testing the endpoints:

1. Initial Login:
```bash
curl -X POST http://localhost:8081/api/customer/login \
  -H "Content-Type: application/json" \
  -d '{"email":"example@email.com", "password":"yourpassword"}'
```

2. Subsequent Login:
```bash
curl -X POST http://localhost:8081/api/customer/login/subsequent \
  -H "Content-Type: application/json" \
  -d '{"username":"example@email.com", "password":"yourpassword"}'
```

3. Get Available Endpoints:
```bash
curl -X GET http://localhost:8081/api/customer/available-endpoints \
  -H "Authorization: Bearer your_jwt_token_here"
```
