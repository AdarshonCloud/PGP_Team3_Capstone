package com.ascendpgp.customerlogin.controller.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.ascendpgp.customerlogin.Service.CustomerService;
import com.ascendpgp.customerlogin.controller.CustomerController;
import com.ascendpgp.customerlogin.model.LoginResponse;

class CustomerControllerTest {

    @Mock
    private CustomerService customerService;

    @InjectMocks
    private CustomerController customerController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void loginTest() {
        // Arrange
        LoginResponse response = new LoginResponse();
        response.setToken("dummyToken");
        response.setFirstName("John");
        response.setLastName("Doe");
        when(customerService.login(anyString(), anyString())).thenReturn(response);

        // Act
        ResponseEntity<?> result = customerController.login(Map.of("email", "test@example.com", "password", "password"));

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody().toString().contains("dummyToken"));
    }

    @Test
    void loginFailTest() {
        // Arrange
        when(customerService.login(anyString(), anyString())).thenThrow(new RuntimeException("Invalid email or password"));

        // Act
        ResponseEntity<?> result = customerController.login(Map.of("email", "test@example.com", "password", "password"));

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertTrue(result.getBody().toString().contains("Invalid email or password"));
    }

    @Test
    void forgotPasswordTest() {
        // Arrange
        doNothing().when(customerService).requestPasswordReset(anyString());

        // Act
        ResponseEntity<?> result = customerController.forgotPassword(Map.of("email", "test@example.com"));

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody().toString().contains("Password reset link sent successfully"));
    }

    @Test
    void resetPasswordTest() {
        // Arrange
        doNothing().when(customerService).resetPasswordForForgotFlow(anyString(), anyString(), anyString());

        // Act
        ResponseEntity<?> result = customerController.forgotPassword(Map.of("token", "validToken", "newPassword", "newPassword", "confirmPassword", "newPassword"));

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody().toString().contains("Password has been reset successfully"));
    }

    @Test
    void changePasswordTest() {
        // Arrange
        doNothing().when(customerService).changePassword(anyString(), anyString(), anyString());

        // Act
        ResponseEntity<?> result = customerController.changePassword(Map.of("currentPassword", "oldPassword", "newPassword", "newPassword", "confirmPassword", "newPassword"));
    }
}
