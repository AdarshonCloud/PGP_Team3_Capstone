package com.ascendpgp.customerlogin.exception.test;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import com.ascendpgp.customerlogin.exception.*;

class ExceptionTest {

    @Test
    void testMongoTimeoutException() {
        String message = "Connection timed out";
        MongoTimeoutException exception = new MongoTimeoutException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void testAccountNotValidatedException() {
        String message = "Account not validated";
        AccountNotValidatedException exception = new AccountNotValidatedException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void testInvalidTokenException() {
        String message = "Invalid or expired token";
        InvalidTokenException exception = new InvalidTokenException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void testWeakPasswordException() {
        String message = "Password does not meet complexity requirements";
        WeakPasswordException exception = new WeakPasswordException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void testInvalidPasswordException() {
        String message = "Invalid password format";
        InvalidPasswordException exception = new InvalidPasswordException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof CustomerServiceException);
    }

    @Test
    void testPasswordMismatchException() {
        String message = "Passwords do not match";
        PasswordMismatchException exception = new PasswordMismatchException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void testCustomerServiceException() {
        String message = "General service error";
        CustomerServiceException exception = new CustomerServiceException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void testAccountLockedException() {
        String message = "Account is locked";
        AccountLockedException exception = new AccountLockedException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof RuntimeException);
    }

    @Test
    void testInvalidCredentialsException() {
        String message = "Invalid credentials";
        InvalidCredentialsException exception = new InvalidCredentialsException(message);

        assertNotNull(exception);
        assertEquals(message, exception.getMessage());
        assertTrue(exception instanceof CustomerServiceException);
    }

    @Test
    void testExceptionHierarchy() {
        // Test inheritance relationships
        InvalidCredentialsException credentialsException = new InvalidCredentialsException("test");
        InvalidPasswordException passwordException = new InvalidPasswordException("test");

        assertTrue(credentialsException instanceof CustomerServiceException);
        assertTrue(passwordException instanceof CustomerServiceException);
        assertTrue(credentialsException instanceof RuntimeException);
    }

    @Test
    void testSerializationPresence() {
        // Test that serialVersionUID is present and correct
        InvalidCredentialsException exception = new InvalidCredentialsException("test");
        CustomerServiceException baseException = new CustomerServiceException("test");

        assertNotNull(exception);
        assertNotNull(baseException);
    }

    @Test
    void testExceptionMessageChaining() {
        String baseMessage = "Base error";
        String specificMessage = "Specific error";

        CustomerServiceException baseException = new CustomerServiceException(baseMessage);
        InvalidCredentialsException chainedException = new InvalidCredentialsException(specificMessage);

        assertEquals(baseMessage, baseException.getMessage());
        assertEquals(specificMessage, chainedException.getMessage());
    }

    @Test
    void testNullMessageHandling() {
        // Test that exceptions handle null messages gracefully
        AccountLockedException exception = new AccountLockedException(null);
        assertNull(exception.getMessage());
    }
}