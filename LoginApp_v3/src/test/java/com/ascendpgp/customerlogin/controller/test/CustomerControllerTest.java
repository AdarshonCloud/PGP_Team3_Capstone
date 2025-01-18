package com.ascendpgp.customerlogin.controller.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.ascendpgp.customerlogin.controller.CustomerController;
import com.ascendpgp.customerlogin.service.CustomerService;
import com.ascendpgp.customerlogin.model.*;
import com.ascendpgp.customerlogin.dto.*;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.exception.*;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomerControllerTest {

    @Mock
    private CustomerService customerService;

    @Mock
    private CustomerRepository customerRepository;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private CustomerController customerController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void firstTimeLogin_Success() {
        LoginRequest request = createLoginRequest();
        LoginResponse mockResponse = createLoginResponse(true);

        when(customerService.login(any(LoginRequest.class), eq(true))).thenReturn(mockResponse);

        ResponseEntity<?> response = customerController.firstTimeLogin(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    void subsequentLogin_Success() {
        LoginRequest request = createLoginRequest();
        LoginResponse mockResponse = createLoginResponse(true);

        when(customerService.login(any(LoginRequest.class), eq(false))).thenReturn(mockResponse);

        ResponseEntity<?> response = customerController.subsequentLogin(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(mockResponse, response.getBody());
    }

    @Test
    void subsequentLogin_InvalidCredentials() {
        LoginRequest request = createLoginRequest();
        when(customerService.login(any(LoginRequest.class), eq(false)))
                .thenThrow(new InvalidCredentialsException("Invalid credentials"));

        ResponseEntity<?> response = customerController.subsequentLogin(request);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    void changePassword_Success() {
        ChangePasswordRequest request = new ChangePasswordRequest();
        request.setCurrentPassword("Current@123");
        request.setNewPassword("New@123");
        request.setConfirmPassword("New@123");

        doNothing().when(customerService).changePassword(
                request.getCurrentPassword(),
                request.getNewPassword(),
                request.getConfirmPassword()
        );

        ResponseEntity<?> response = customerController.changePassword(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void handleResetPasswordLink_Success() {
        String token = "valid-token";
        CustomerEntity customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1));

        when(customerRepository.findByResetPasswordToken(token)).thenReturn(customer);

        ResponseEntity<?> response = customerController.handleResetPasswordLink(token);

        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void handleResetPasswordLink_ExpiredToken() {
        String token = "expired-token";
        CustomerEntity customer = new CustomerEntity();
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().minusHours(1));

        when(customerRepository.findByResetPasswordToken(token)).thenReturn(customer);

        ResponseEntity<?> response = customerController.handleResetPasswordLink(token);

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void resetPassword_Success() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("valid-token");
        request.setNewPassword("New@123");
        request.setConfirmPassword("New@123");

        doNothing().when(customerService).resetPasswordForForgotFlow(
                request.getToken(),
                request.getNewPassword(),
                request.getConfirmPassword()
        );

        ResponseEntity<?> response = customerController.resetPassword(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void logout_Success() {
        String token = "Bearer valid-token";
        when(customerService.logout(anyString())).thenReturn(true);

        ResponseEntity<?> response = customerController.logout(token);

        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    private LoginRequest createLoginRequest() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        request.setPassword(Base64.getEncoder().encodeToString("Test@123".getBytes()));
        return request;
    }

    private LoginResponse createLoginResponse(boolean validated) {
        LoginResponse response = new LoginResponse();
        response.setToken("test-token");
        CustomerEntity.Name name = new CustomerEntity.Name("John", "Doe");
        response.setName(name);
        response.setAccountValidated(validated);
        return response;
    }

    private jakarta.servlet.http.HttpServletRequest mockRequest(String authHeader) {
        jakarta.servlet.http.HttpServletRequest request = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn(authHeader);
        return request;
    }
}