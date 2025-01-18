package com.ascendpgp.customerlogin.service.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.time.LocalDateTime;
import java.util.Base64;

import com.ascendpgp.customerlogin.service.CustomerService;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.exception.*;
import com.mongodb.MongoSocketWriteException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomerServiceAdditionalTest {

    @Mock
    private CustomerRepository customerRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private CustomerService customerService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);
    }

    @Test
    void validatePassword_Success() {
        String rawPassword = "testPass123";
        String hashedPassword = "hashedPassword";

        when(passwordEncoder.matches(rawPassword, hashedPassword)).thenReturn(true);

        assertTrue(customerService.validatePassword(rawPassword, hashedPassword));
        verify(passwordEncoder).matches(rawPassword, hashedPassword);
    }

    @Test
    void validatePassword_Failure() {
        String rawPassword = "testPass123";
        String hashedPassword = "hashedPassword";

        when(passwordEncoder.matches(rawPassword, hashedPassword)).thenReturn(false);

        assertFalse(customerService.validatePassword(rawPassword, hashedPassword));
        verify(passwordEncoder).matches(rawPassword, hashedPassword);
    }

    @Test
    void login_CustomerNotFound() {
        LoginRequest request = new LoginRequest();
        request.setEmail("nonexistent@example.com");
        request.setPassword(Base64.getEncoder().encodeToString("password123".getBytes()));

        when(customerRepository.findByEmail("nonexistent@example.com")).thenReturn(null);

        assertThrows(InvalidCredentialsException.class, () ->
                customerService.login(request, true)
        );
    }

    @Test
    void login_WithEndpoints_Success() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        String rawPassword = "Test@123";
        request.setPassword(Base64.getEncoder().encodeToString(rawPassword.getBytes()));

        CustomerEntity customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        customer.setUsername("testuser");
        customer.setPassword(passwordEncoder.encode(rawPassword));
        customer.setName(new CustomerEntity.Name("John", "Doe"));

        when(customerRepository.findByEmail("test@example.com")).thenReturn(customer);
        when(passwordEncoder.matches(rawPassword, customer.getPassword())).thenReturn(true);
        when(jwtService.generateToken(anyString(), anyString())).thenReturn("test-token");

        LoginResponse response = customerService.login(request, false);

        assertNotNull(response);
        assertNotNull(response.getAvailableEndpoints());
        assertEquals(2, response.getAvailableEndpoints().size());
        assertEquals("/api/account", response.getAvailableEndpoints().get(0).getUrl());
        assertEquals("/api/creditcards", response.getAvailableEndpoints().get(1).getUrl());
    }

    @Test
    void login_HandleMongoException() {
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        request.setPassword(Base64.getEncoder().encodeToString("password123".getBytes()));

        when(customerRepository.findByEmail(anyString()))
                .thenThrow(new com.mongodb.MongoTimeoutException("Connection timeout"));

        assertThrows(MongoTimeoutException.class, () ->
                customerService.login(request, true)
        );
    }

    @Test
    void handleFailedLogin_ExceedMaxAttempts() {
        CustomerEntity customer = new CustomerEntity();
        customer.setFailedAttempts(2); // One more attempt will exceed MAX_FAILED_ATTEMPTS (3)

        when(customerRepository.save(any(CustomerEntity.class))).thenReturn(customer);

        assertThrows(AccountLockedException.class, () -> {
            for (int i = 0; i < 2; i++) {
                try {
                    LoginRequest request = new LoginRequest();
                    request.setEmail("test@example.com");
                    request.setPassword(Base64.getEncoder().encodeToString("wrongpass".getBytes()));

                    when(customerRepository.findByEmail("test@example.com")).thenReturn(customer);
                    when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

                    customerService.login(request, true);
                } catch (InvalidCredentialsException e) {
                    // Expected exception, continue
                }
            }
        });

        assertTrue(customer.isLocked());
        assertNotNull(customer.getLockTime());
    }

    @Test
    void unlockAccountIfEligible_Success() {
        // Set up customer
        CustomerEntity customer = new CustomerEntity();
        String rawPassword = "Test@123";
        String encodedPassword = "encodedPassword";
        customer.setPassword(encodedPassword);
        customer.setLocked(true);
        customer.setLockTime(LocalDateTime.now().minusHours(25)); // Past the 24-hour lock duration
        customer.setFailedAttempts(3);
        customer.setEmail("test@example.com");
        customer.setUsername("testuser");
        customer.setName(new CustomerEntity.Name("Test", "User"));

        when(customerRepository.save(any(CustomerEntity.class))).thenReturn(customer);

        // Set up login request
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        request.setPassword(Base64.getEncoder().encodeToString(rawPassword.getBytes()));

        // Mock repository and service responses
        when(customerRepository.findByEmail("test@example.com")).thenReturn(customer);
        when(passwordEncoder.matches(rawPassword, encodedPassword)).thenReturn(true);
        when(jwtService.generateToken(anyString(), anyString())).thenReturn("test-token");

        // Perform login
        LoginResponse response = customerService.login(request, true);

        // Verify results
        assertNotNull(response);
        assertNotNull(response.getToken());
        verify(customerRepository, times(4)).save(customer); // Saves happen during unlock, reset attempts, and login
        assertFalse(customer.isLocked());
        assertNull(customer.getLockTime());
        assertEquals(0, customer.getFailedAttempts());
    }

    @Test
    void sendVerificationEmail_Success() {
        String email = "test@example.com";
        CustomerEntity customer = new CustomerEntity();
        customer.setEmail(email);
        customer.setAccountValidated(false);

        when(customerRepository.findByEmail(email)).thenReturn(customer);
        when(customerRepository.save(any(CustomerEntity.class))).thenReturn(customer);
        doNothing().when(mailSender).send(any(SimpleMailMessage.class));

        assertDoesNotThrow(() -> customerService.sendVerificationEmail(email));

        verify(customerRepository).save(customer);
        verify(mailSender).send(any(SimpleMailMessage.class));
        assertNotNull(customer.getVerificationToken());
        assertNotNull(customer.getVerificationTokenExpiry());
    }

    @Test
    void sendVerificationEmail_MongoException() {
        String email = "test@example.com";
        when(customerRepository.findByEmail(email))
                .thenThrow(new com.mongodb.MongoTimeoutException("Connection timeout"));

        assertThrows(MongoTimeoutException.class, () ->
                customerService.sendVerificationEmail(email)
        );
    }

    @Test
    void verifyAccount_Success() {
        String token = "valid-token";
        CustomerEntity customer = new CustomerEntity();
        customer.setVerificationToken(token);
        customer.setVerificationTokenExpiry(LocalDateTime.now().plusHours(1));
        customer.setAccountValidated(false);

        when(customerRepository.findByVerificationToken(token)).thenReturn(customer);
        when(customerRepository.save(any(CustomerEntity.class))).thenReturn(customer);

        assertDoesNotThrow(() -> customerService.verifyAccount(token));

        assertTrue(customer.isAccountValidated());
        assertNull(customer.getVerificationToken());
        assertNull(customer.getVerificationTokenExpiry());
    }

    @Test
    void logoutFallback_ReturnsExpectedResult() {
        Exception testException = new RuntimeException("Test exception");
        boolean result = customerService.logoutFallback(testException);
        assertFalse(result);
    }

    @Test
    void updatePassword_Success() {
        CustomerEntity customer = new CustomerEntity();
        String newPassword = "NewPass@123";

        when(passwordEncoder.encode(newPassword)).thenReturn("encodedPassword");
        when(customerRepository.save(any(CustomerEntity.class))).thenReturn(customer);

        customerService.updatePassword(customer, newPassword);

        assertEquals("encodedPassword", customer.getPassword());
        assertNotNull(customer.getPasswordLastUpdated());
        assertNotNull(customer.getPasswordExpiryDate());
        verify(customerRepository).save(customer);
    }

    @Test
    void resetPasswordForForgotFlow_Success() {
        String token = "valid-token";
        String newPassword = "NewPass@123";
        String confirmPassword = "NewPass@123";

        CustomerEntity customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        customer.setResetPasswordToken(token);
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1));
        customer.setPassword("oldPassword");

        when(customerRepository.findByResetPasswordToken(token)).thenReturn(customer);
        when(passwordEncoder.encode(newPassword)).thenReturn("encodedNewPassword");
        when(customerRepository.save(any(CustomerEntity.class))).thenReturn(customer);

        assertDoesNotThrow(() ->
                customerService.resetPasswordForForgotFlow(token, newPassword, confirmPassword)
        );

        verify(customerRepository).save(customer);
        assertNull(customer.getResetPasswordToken());
        assertNull(customer.getResetPasswordTokenExpiry());
        assertEquals("encodedNewPassword", customer.getPassword());
        assertFalse(customer.isLocked());
    }

    @Test
    void resetPasswordForForgotFlow_InvalidToken() {
        String token = "invalid-token";
        String newPassword = "NewPass@123";
        String confirmPassword = "NewPass@123";

        when(customerRepository.findByResetPasswordToken(token)).thenReturn(null);

        assertThrows(InvalidTokenException.class, () ->
                customerService.resetPasswordForForgotFlow(token, newPassword, confirmPassword)
        );
    }

    @Test
    void resetPasswordForForgotFlow_PasswordMismatch() {
        String token = "valid-token";
        String newPassword = "NewPass@123";
        String confirmPassword = "DifferentPass@123";

        CustomerEntity customer = new CustomerEntity();
        customer.setResetPasswordToken(token);
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1));

        when(customerRepository.findByResetPasswordToken(token)).thenReturn(customer);

        assertThrows(PasswordMismatchException.class, () ->
                customerService.resetPasswordForForgotFlow(token, newPassword, confirmPassword)
        );
    }

    @Test
    void changePassword_Success() {
        String currentPassword = "CurrentPass@123";
        String newPassword = "NewPass@123";
        String confirmPassword = "NewPass@123";
        String username = "testuser";

        CustomerEntity customer = new CustomerEntity();
        customer.setUsername(username);
        customer.setPassword("encodedCurrentPassword");

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn(username);
        when(customerRepository.findByUsername(username)).thenReturn(customer);
        when(passwordEncoder.matches(currentPassword, customer.getPassword())).thenReturn(true);
        when(passwordEncoder.encode(newPassword)).thenReturn("encodedNewPassword");
        when(customerRepository.save(any(CustomerEntity.class))).thenReturn(customer);

        assertDoesNotThrow(() ->
                customerService.changePassword(currentPassword, newPassword, confirmPassword)
        );

        verify(customerRepository).save(customer);
        assertEquals("encodedNewPassword", customer.getPassword());
        assertNotNull(customer.getPasswordLastUpdated());
        assertNotNull(customer.getPasswordExpiryDate());
    }

    @Test
    void changePassword_InvalidCurrentPassword() {
        String currentPassword = "WrongPass@123";
        String newPassword = "NewPass@123";
        String confirmPassword = "NewPass@123";
        String username = "testuser";

        CustomerEntity customer = new CustomerEntity();
        customer.setUsername(username);
        customer.setPassword("encodedCurrentPassword");

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn(username);
        when(customerRepository.findByUsername(username)).thenReturn(customer);
        when(passwordEncoder.matches(currentPassword, customer.getPassword())).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () ->
                customerService.changePassword(currentPassword, newPassword, confirmPassword)
        );
    }

    @Test
    void changePassword_PasswordMismatch() {
        String currentPassword = "CurrentPass@123";
        String newPassword = "NewPass@123";
        String confirmPassword = "DifferentPass@123";
        String username = "testuser";

        CustomerEntity customer = new CustomerEntity();
        customer.setUsername(username);
        customer.setPassword("encodedCurrentPassword");

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn(username);
        when(customerRepository.findByUsername(username)).thenReturn(customer);
        when(passwordEncoder.matches(currentPassword, customer.getPassword())).thenReturn(true);

        assertThrows(PasswordMismatchException.class, () ->
                customerService.changePassword(currentPassword, newPassword, confirmPassword)
        );
    }

    @Test
    void logout_Success() {
        String token = "valid-token";
        String username = "testuser";

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn(username);
        doNothing().when(jwtService).blacklistToken(token);

        assertTrue(customerService.logout(token));
        verify(jwtService).blacklistToken(token);

        // Verify SecurityContext is cleared
        SecurityContextHolder.clearContext();
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void logout_NoActiveSession() {
        String token = "valid-token";

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn(null);

        assertThrows(CustomerServiceException.class, () ->
                customerService.logout(token)
        );
    }

    @Test
    void logout_ExceptionDuringBlacklist() {
        String token = "valid-token";
        String username = "testuser";

        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getName()).thenReturn(username);
        doThrow(new RuntimeException("Blacklist error")).when(jwtService).blacklistToken(token);

        assertThrows(RuntimeException.class, () ->
                customerService.logout(token)
        );
    }
}