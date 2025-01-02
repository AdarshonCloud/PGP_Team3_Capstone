package com.ascendpgp.customerlogin.service.test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ascendpgp.customerlogin.service.CustomerService;
import com.ascendpgp.customerlogin.exception.CustomerServiceException;
import com.ascendpgp.customerlogin.exception.InvalidCredentialsException;
import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import jakarta.mail.internet.MimeMessage;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;

class CustomerServiceTest {

    @InjectMocks
    private CustomerService customerService;

    @Mock
    private CustomerRepository customerRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private JavaMailSender mailSender;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // Test Case 1: Successful Login for First-Time Login
    @Test
    void testLogin_Success_FirstTimeLogin() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        CustomerEntity customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        customer.setPassword("encodedPassword");
        customer.setName(new CustomerEntity.Name("John", "Doe"));
        customer.setAccountValidated(true);
        customer.setFirstTimeLogin(true);

        when(customerRepository.findByEmail("test@example.com")).thenReturn(customer);
        when(passwordEncoder.matches("password123", "encodedPassword")).thenReturn(true);
        when(jwtService.generateToken(anyString(), anyString())).thenReturn("dummy-token");

        LoginResponse response = customerService.login(loginRequest, true);

        assertNotNull(response);
        assertEquals("dummy-token", response.getToken());
        assertTrue(response.isAccountValidated());
        assertEquals("John", response.getName().getFirst());
        assertEquals("Doe", response.getName().getLast());
        verify(customerRepository, times(1)).save(customer);
    }

    // Test Case 2: Login Failure Due to Invalid Password
    @Test
    void testLogin_Failure_InvalidPassword() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("wrongPassword");

        CustomerEntity customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        customer.setPassword("encodedPassword");

        when(customerRepository.findByEmail("test@example.com")).thenReturn(customer);
        when(passwordEncoder.matches("wrongPassword", "encodedPassword")).thenReturn(false);

        Exception exception = assertThrows(CustomerServiceException.class, () ->
                customerService.login(loginRequest, false));

        assertEquals("Invalid email or password.", exception.getMessage());
    }

 // Test Case 3: Login Failure Due to CircuitBreaker Open
    @Test
    void testLogin_CircuitBreakerOpen() {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        // Mock the CircuitBreaker
        CircuitBreaker circuitBreaker = mock(CircuitBreaker.class);
        CallNotPermittedException circuitBreakerException = CallNotPermittedException.createCallNotPermittedException(circuitBreaker);

        when(customerRepository.findByEmail(anyString())).thenThrow(circuitBreakerException);

        Exception exception = assertThrows(CallNotPermittedException.class, () ->
                customerService.login(loginRequest, true));

        assertTrue(exception instanceof CallNotPermittedException);
        assertEquals("CircuitBreaker 'null' is OPEN and does not permit further calls", exception.getMessage());
    }

    // Test Case 4: Send Verification Email Successfully
    @Test
    void testSendVerificationEmail_Success() {
        CustomerEntity customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        customer.setAccountValidated(false);

        // Mock the repository to return the customer entity
        when(customerRepository.findByEmail("test@example.com")).thenReturn(customer);

        // Mock the behavior of JavaMailSender
        MimeMessage mimeMessage = mock(MimeMessage.class);
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);

        doNothing().when(mailSender).send(any(MimeMessage.class));

        // Call the method under test
        customerService.sendVerificationEmail("test@example.com");

        // Verify that the email was sent and the customer was saved
        verify(mailSender, times(1)).send(any(MimeMessage.class));
        verify(customerRepository, times(1)).save(customer);
    }	

    // Test Case 5: Password Reset for Forgot Password Flow - Success
    @Test
    void testResetPasswordForForgotFlow_Success() {
        CustomerEntity customer = new CustomerEntity();
        customer.setResetPasswordToken("valid-token");
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().plusMinutes(30));
        customer.setPasswordHistory(List.of("oldEncodedPassword"));

        when(customerRepository.findByResetPasswordToken("valid-token")).thenReturn(customer);
        when(passwordEncoder.encode("newPassword123")).thenReturn("encodedPassword");

        customerService.resetPasswordForForgotFlow("valid-token", "newPassword123", "newPassword123");

        verify(customerRepository, times(1)).save(customer);
        assertNull(customer.getResetPasswordToken());
        assertNull(customer.getResetPasswordTokenExpiry());
        assertEquals("encodedPassword", customer.getPassword());
    }

    // Test Case 6: Password Reset for Forgot Password Flow - Failure (Expired Token)
    @Test
    void testResetPasswordForForgotFlow_Failure_TokenExpired() {
        CustomerEntity customer = new CustomerEntity();
        customer.setResetPasswordToken("expired-token");
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().minusMinutes(1));

        when(customerRepository.findByResetPasswordToken("expired-token")).thenReturn(customer);

        Exception exception = assertThrows(InvalidTokenException.class, () ->
                customerService.resetPasswordForForgotFlow("expired-token", "newPassword123", "newPassword123"));

        assertEquals("Invalid or expired reset token.", exception.getMessage());
    }

    // Test Case 7: Password Change - Success
    @Test
    void testChangePassword_Success() {
        CustomerEntity customer = new CustomerEntity();
        customer.setUsername("testuser");
        customer.setPassword("encodedPassword");
        customer.setPasswordHistory(new ArrayList<>());

        when(customerRepository.findByUsername("testuser")).thenReturn(customer);
        when(passwordEncoder.matches("currentPassword", "encodedPassword")).thenReturn(true);
        when(passwordEncoder.encode("newPassword")).thenReturn("newEncodedPassword");

        customerService.changePassword("currentPassword", "newPassword", "newPassword");

        verify(customerRepository, times(1)).save(customer);
        assertEquals("newEncodedPassword", customer.getPassword());
    }

    // Test Case 8: Password Change - Failure (Invalid Current Password)
    @Test
    void testChangePassword_Failure_InvalidCurrentPassword() {
        CustomerEntity customer = new CustomerEntity();
        customer.setUsername("testuser");
        customer.setPassword("encodedPassword");

        when(customerRepository.findByUsername("testuser")).thenReturn(customer);
        when(passwordEncoder.matches("wrongPassword", "encodedPassword")).thenReturn(false);

        Exception exception = assertThrows(InvalidCredentialsException.class, () ->
                customerService.changePassword("wrongPassword", "newPassword", "newPassword"));

        assertEquals("Current password is incorrect.", exception.getMessage());
    }
}