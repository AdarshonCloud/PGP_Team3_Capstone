package com.ascendpgp.customerlogin.controller.test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.ascendpgp.customerlogin.service.CustomerService;
import com.ascendpgp.customerlogin.controller.CustomerController;
import com.ascendpgp.customerlogin.dto.ForgotPasswordRequest;
import com.ascendpgp.customerlogin.dto.ResetPasswordRequest;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.exception.InvalidTokenException;

class CustomerControllerTest {

    @Mock
    private CustomerService customerService;

    @InjectMocks
    private CustomerController customerController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // Test Case 1: First-Time Login Success
    @Test
    public void testFirstTimeLogin_Success() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        LoginResponse mockResponse = new LoginResponse();
        mockResponse.setName(new CustomerEntity.Name("John", "Doe"));
        mockResponse.setToken("dummy-token");
        mockResponse.setAccountValidated(false);

        when(customerService.login(any(LoginRequest.class), eq(true))).thenReturn(mockResponse);

        ResponseEntity<?> response = customerController.firstTimeLogin(loginRequest);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertNotNull(body);
        assertEquals("Welcome John Doe", body.get("message"));
        assertEquals("dummy-token", body.get("token"));
        verify(customerService, times(1)).login(any(LoginRequest.class), eq(true));
    }

    // Test Case 2: First-Time Login Failure
    @Test
    public void testFirstTimeLogin_Failure() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("invalid@example.com");
        loginRequest.setPassword("wrongPassword");

        when(customerService.login(any(LoginRequest.class), eq(true)))
                .thenThrow(new RuntimeException("Invalid email or password."));

        ResponseEntity<?> response = customerController.firstTimeLogin(loginRequest);

        assertNotNull(response);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Invalid email or password.", ((Map<?, ?>) response.getBody()).get("error"));
        verify(customerService, times(1)).login(any(LoginRequest.class), eq(true));
    }

    // Test Case 3: Subsequent Login Success
    @Test
    public void testSubsequentLogin_Success() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        LoginResponse mockResponse = new LoginResponse();
        mockResponse.setName(new CustomerEntity.Name("John", "Doe"));
        mockResponse.setToken("dummy-token");

        when(customerService.login(any(LoginRequest.class), eq(false))).thenReturn(mockResponse);

        ResponseEntity<?> response = customerController.subsequentLogin(loginRequest);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(mockResponse, response.getBody());
        verify(customerService, times(1)).login(any(LoginRequest.class), eq(false));
    }

    // Test Case 4: Forgot Password Success
    @Test
    public void testForgotPassword_Success() {
        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmail("test@example.com");

        doNothing().when(customerService).requestPasswordReset(request.getEmail());

        ResponseEntity<?> response = customerController.forgotPassword(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Password reset link sent to your email.", response.getBody());
        verify(customerService, times(1)).requestPasswordReset(request.getEmail());
    }

    // Test Case 5: Forgot Password Failure
    @Test
    public void testForgotPassword_Failure() {
        // Arrange
        ForgotPasswordRequest request = new ForgotPasswordRequest();
        request.setEmail("nonexistent@example.com");

        doThrow(new RuntimeException("Email not found.")).when(customerService).requestPasswordReset(request.getEmail());

        // Act
        ResponseEntity<?> result = customerController.forgotPassword(request);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals("Email not found.", ((Map<?, ?>) result.getBody()).get("error"));
        verify(customerService, times(1)).requestPasswordReset(request.getEmail());
    }

 // Test Case 3: Reset Password Success
    @Test
    public void testResetPassword_Success() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("valid-token");
        request.setNewPassword("newPassword123");
        request.setConfirmPassword("newPassword123");

        doNothing().when(customerService).resetPasswordForForgotFlow(
                request.getToken(), request.getNewPassword(), request.getConfirmPassword()
        );

        ResponseEntity<?> response = customerController.resetPassword(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Password reset successfully.", response.getBody());
        verify(customerService, times(1)).resetPasswordForForgotFlow(
                request.getToken(), request.getNewPassword(), request.getConfirmPassword()
        );
    }

    // Test Case 7: Reset Password Failure
    @Test
    public void testResetPassword_Failure() {
        // Arrange
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("expired-token");
        request.setNewPassword("newPassword123");
        request.setConfirmPassword("newPassword123");

        doThrow(new RuntimeException("Invalid or expired token."))
                .when(customerService).resetPasswordForForgotFlow(
                        request.getToken(), request.getNewPassword(), request.getConfirmPassword()
                );

        // Act
        ResponseEntity<?> result = customerController.resetPassword(request);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals("Invalid or expired token.", ((Map<?, ?>) result.getBody()).get("error"));
        verify(customerService, times(1)).resetPasswordForForgotFlow(
                request.getToken(), request.getNewPassword(), request.getConfirmPassword()
        );
    }

    // Test Case 8: Verify Account Success
    @Test
    public void testVerifyAccount_Success() {
        doNothing().when(customerService).verifyAccount(anyString());

        ResponseEntity<?> result = customerController.verifyAccount("valid-token");

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals("Account verified successfully.", result.getBody());
        verify(customerService, times(1)).verifyAccount("valid-token");
    }

    // Test Case 9: Verify Account Failure
    @Test
    public void testVerifyAccount_Failure() {
        doThrow(new InvalidTokenException("Invalid or expired token."))
                .when(customerService).verifyAccount(anyString());

        ResponseEntity<?> result = customerController.verifyAccount("expired-token");

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals("Invalid or expired token.", ((Map<?, ?>) result.getBody()).get("error"));
        verify(customerService, times(1)).verifyAccount("expired-token");
    }
}