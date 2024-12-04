package com.ascendpgp.customerlogin.service.test;

import com.ascendpgp.customerlogin.Service.CustomerService;
import com.ascendpgp.customerlogin.exception.*;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.utils.PasswordValidator;

import jakarta.mail.internet.MimeMessage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomerServiceTest {

    @Mock
    private CustomerRepository customerRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JavaMailSender mailSender;

    @InjectMocks
    private CustomerService customerService;

    private CustomerEntity customer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);  // Initialize mocks
        customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        customer.setFirstName("John");
        customer.setLastName("Doe");
        customer.setPassword("hashedPassword");
        customer.setAccountValidated(true);
    }

    @Test
    void loginSuccessTest() {
        // Arrange
        when(customerRepository.findByEmail(anyString())).thenReturn(customer);
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(jwtService.generateToken(anyString())).thenReturn("dummyToken");

        // Act
        LoginResponse response = customerService.login("test@example.com", "password");

        // Assert
        assertNotNull(response);
        assertEquals("dummyToken", response.getToken());
        assertEquals("John", response.getFirstName());
        assertTrue(response.isAccountValidated());
    }

    @Test
    void loginInvalidCredentialsTest() {
        // Arrange
        when(customerRepository.findByEmail(anyString())).thenReturn(null);

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            customerService.login("invalid@example.com", "password");
        });

        assertEquals("Invalid email or password.", exception.getMessage());
    }

    @Test
    void requestPasswordResetTest() {
        // Arrange
        when(customerRepository.findByEmail(anyString())).thenReturn(customer);  // Mocking customer lookup

        // Act
        customerService.requestPasswordReset("test@example.com");  // Calling the service method

        // Assert
        verify(customerRepository, times(1)).save(any());  // Verifying save was called on customerRepository
        verify(mailSender, times(1)).send((MimeMessagePreparator) any(MimeMessage.class));  // Verifying send was called on JavaMailSender
    }

    @Test
    void resetPasswordForForgotFlowTestSuccess() {
        // Arrange: Create a customer with a valid reset token and token expiry time
        String resetToken = "valid-token"; // This token should match what's expected in your service
        CustomerEntity customer = new CustomerEntity();
        customer.setResetPasswordToken(resetToken);
        
        // Convert long timestamp (milliseconds) to LocalDateTime
        LocalDateTime expiryTime = LocalDateTime.now().plusHours(1); // Set expiry time to 1 hour from now
        customer.setResetPasswordTokenExpiry(expiryTime); 

        when(customerRepository.findByResetPasswordToken(resetToken)).thenReturn(customer);

        // Act: Call the reset password method
        customerService.resetPasswordForForgotFlow(resetToken, "newPassword123", "newPassword123");

        // Assert: Verify that the reset password logic works
        verify(customerRepository, times(1)).save(customer);
    }



    @Test
    void resetPasswordForForgotFlowTestInvalidToken() {
        // Arrange
        when(customerRepository.findByResetPasswordToken(anyString())).thenReturn(null);

        // Act & Assert
        InvalidTokenException exception = assertThrows(InvalidTokenException.class, () -> {
            customerService.resetPasswordForForgotFlow("invalidToken", "newPassword", "newPassword");
        });

        assertEquals("Invalid or expired reset token.", exception.getMessage());
    }

    @Test
    void changePasswordSuccessTest() {
        // Arrange
        when(customerRepository.findByUsername(anyString())).thenReturn(customer);
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

        // Act
        customerService.changePassword("oldPassword", "newPassword", "newPassword");

        // Assert
        verify(customerRepository, times(1)).save(any());
    }

    @Test
    void changePasswordInvalidCurrentPasswordTest() {
        // Arrange
        when(customerRepository.findByUsername(anyString())).thenReturn(customer);
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            customerService.changePassword("wrongPassword", "newPassword", "newPassword");
        });

        assertEquals("Current password is incorrect.", exception.getMessage());
    }
}
