//package com.ascendpgp.customerlogin.exception.test;
//
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.junit.jupiter.MockitoExtension;
//import org.slf4j.Logger;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.servlet.NoHandlerFoundException;
//
//import com.ascendpgp.customerlogin.exception.*;
//
//import static org.mockito.ArgumentMatchers.any;
//import static org.mockito.ArgumentMatchers.eq;
//import static org.mockito.Mockito.*;
//import static org.junit.jupiter.api.Assertions.*;
//
//import java.util.Map;
//
//@ExtendWith(MockitoExtension.class)
//class GlobalExceptionHandlerTest {
//
//    static class TestGlobalExceptionHandler extends GlobalExceptionHandler {
//        private final Logger logger;
//
//        TestGlobalExceptionHandler(Logger logger) {
//            this.logger = logger;
//        }
//
//        @Override
//        protected Logger getLogger() {
//            return this.logger;
//        }
//    }
//
//    private TestGlobalExceptionHandler exceptionHandler;
//    private Logger mockLogger;
//
//    @BeforeEach
//    void setUp() {
//        mockLogger = mock(Logger.class);
//        exceptionHandler = new TestGlobalExceptionHandler(mockLogger);
//    }
//
//    @Test
//    void testHandleInvalidCredentials() {
//        String errorMessage = "Invalid credentials";
//        InvalidCredentialsException ex = new InvalidCredentialsException(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handleInvalidCredentials(ex);
//
//        verify(mockLogger).warn(eq("Authentication error: {}"), any(String.class));
//        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
//        assertEquals("Invalid credentials.", response.getBody().get("error"));
//    }
//
//    @Test
//    void testHandleInvalidToken() {
//        String errorMessage = "Token expired";
//        InvalidTokenException ex = new InvalidTokenException(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handleInvalidToken(ex);
//
//        verify(mockLogger).warn(eq("Token error: {}"), any(String.class));
//        assertEquals(HttpStatus.GONE, response.getStatusCode());
//        assertEquals("Invalid or expired token.", response.getBody().get("error"));
//    }
//
//    @Test
//    void testHandlePasswordMismatch() {
//        String errorMessage = "Passwords don't match";
//        PasswordMismatchException ex = new PasswordMismatchException(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handlePasswordMismatch(ex);
//
//        verify(mockLogger).warn(eq("Password mismatch: {}"), any(String.class));
//        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//        assertEquals(errorMessage, response.getBody().get("error"));
//    }
//
//    @Test
//    void testHandleWeakPassword() {
//        String errorMessage = "Password too weak";
//        WeakPasswordException ex = new WeakPasswordException(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handleWeakPassword(ex);
//
//        verify(mockLogger).warn(eq("Weak password: {}"), any(String.class));
//        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//        assertEquals(errorMessage, response.getBody().get("error"));
//    }
//
//    @Test
//    void testHandleAccountLocked() {
//        String errorMessage = "Account is locked";
//        AccountLockedException ex = new AccountLockedException(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handleAccountLocked(ex);
//
//        verify(mockLogger).warn(eq("Account locked: {}"), any(String.class));
//        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
//        assertEquals("Your account is locked due to multiple failed login attempts. Please try again later or reset your password.",
//                response.getBody().get("error"));
//    }
//
//    @Test
//    void testHandleRuntimeException() {
//        String errorMessage = "Runtime error";
//        RuntimeException ex = new RuntimeException(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handleRuntimeException(ex);
//
//        verify(mockLogger).error(eq("Runtime exception occurred: {}, {}"), any(String.class), any(RuntimeException.class));
//        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//        assertEquals(errorMessage, response.getBody().get("error"));
//    }
//
//    @Test
//    void testHandleGeneralException() {
//        String errorMessage = "General error";
//        Exception ex = new Exception(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handleGeneralException(ex);
//
//        verify(mockLogger).error(eq("Unexpected exception occurred: {}, {}"), any(String.class), any(Exception.class));
//        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//        assertEquals("An unexpected error occurred.", response.getBody().get("error"));
//        assertEquals(errorMessage, response.getBody().get("details"));
//    }
//
//    @Test
//    void testHandle404() throws NoHandlerFoundException {
//        NoHandlerFoundException ex = new NoHandlerFoundException("GET", "/test", null);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handle404(ex);
//
//        verify(mockLogger).warn(eq("404 error: {}"), any(String.class));
//        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
//        assertEquals("The requested resource was not found.", response.getBody().get("error"));
//        assertEquals("Fallback service is invoked for missing endpoint.", response.getBody().get("fallback"));
//    }
//
//    @Test
//    void testHandleMongoTimeoutException() {
//        String errorMessage = "Database timeout";
//        MongoTimeoutException ex = new MongoTimeoutException(errorMessage);
//
//        ResponseEntity<?> response = exceptionHandler.handleMongoTimeoutException(ex);
//
//        verify(mockLogger).error(eq("MongoDB exception occurred: {}, {}"), any(String.class), any(MongoTimeoutException.class));
//        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
//        assertEquals("A database connectivity issue occurred. Please try again later.", response.getBody());
//    }
//
//    @Test
//    void testHandleIllegalArgumentException() {
//        String errorMessage = "Invalid argument";
//        IllegalArgumentException ex = new IllegalArgumentException(errorMessage);
//
//        ResponseEntity<Map<String, String>> response = exceptionHandler.handleIllegalArgumentException(ex);
//
//        verify(mockLogger).warn(eq("Illegal argument: {}"), any(String.class));
//        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
//        assertEquals(errorMessage, response.getBody().get("error"));
//    }
//}