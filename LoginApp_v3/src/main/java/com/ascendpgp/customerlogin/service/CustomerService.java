package com.ascendpgp.customerlogin.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ascendpgp.customerlogin.exception.CustomerServiceException;
import com.ascendpgp.customerlogin.exception.InvalidPasswordException;
import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.exception.PasswordMismatchException;
import com.ascendpgp.customerlogin.exception.WeakPasswordException;
import com.ascendpgp.customerlogin.model.ApiEndpoint;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.utils.PasswordValidator;
import com.mongodb.MongoSocketWriteException;
import org.springframework.stereotype.Service;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;


@Service
public class CustomerService {

    private static final Logger logger = LoggerFactory.getLogger(CustomerService.class);

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    private static final String CUSTOMER_SERVICE = "customerService";
    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int LOCK_TIME_DURATION = 24;

    // Validate password
    public boolean validatePassword(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword, hashedPassword);
    }

    // Login method with Circuit Breaker
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForLogin")
    public LoginResponse login(LoginRequest loginRequest, boolean isFirstTimeLogin) {
        logger.info("Login attempt for email: {}", loginRequest.getEmail());

        // Find customer by email
        CustomerEntity customer = customerRepository.findByEmail(loginRequest.getEmail());
        if (customer == null) {
            logger.warn("Customer not found for email: {}", loginRequest.getEmail());
            throw new CustomerServiceException("Invalid email or password.");
        }

        // Check if account is locked
        if (customer.isLocked()) {
            unlockAccountIfEligible(customer);
            if (customer.isLocked()) {
                throw new CustomerServiceException("Account is locked. Please reset your password or wait 24 hours.");
            }
        }

        // Validate password
        if (!passwordEncoder.matches(loginRequest.getPassword(), customer.getPassword())) {
            handleFailedLogin(customer);
            throw new CustomerServiceException("Invalid email or password.");
        }

        // Reset failed attempts on successful login
        resetFailedAttempts(customer);

        // Check password expiry
        boolean isPasswordExpired = customer.getPasswordExpiryDate() != null &&
                customer.getPasswordExpiryDate().isBefore(LocalDateTime.now());

        // Update firstTimeLogin to false if this is a first-time login
        if (isFirstTimeLogin && customer.isFirstTimeLogin()) {
            customer.setFirstTimeLogin(false);
            customerRepository.save(customer);
            logger.info("First-time login detected for email: {}. Updated firstTimeLogin to false.", loginRequest.getEmail());
        }

        // Generate JWT token
        String token = jwtService.generateToken(customer.getEmail(), customer.getUsername());
        logger.info("JWT token generated for email: {}", loginRequest.getEmail());

        // Prepare and return response
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setName(customer.getName()); // Updated to use the `Name` object
        response.setAccountValidated(customer.isAccountValidated());
        response.setPasswordExpired(isPasswordExpired);

        // Add a validation message if the account is not validated
        if (!customer.isAccountValidated()) {
            logger.warn("Account not validated for email: {}", loginRequest.getEmail());
            response.setMessage(
                    String.format("Welcome %s %s. Your account is not validated. Please verify your account.",
                            customer.getName().getFirst(), customer.getName().getLast())
            );
        } else {
            response.setMessage(
                    String.format("Welcome %s %s.", customer.getName().getFirst(), customer.getName().getLast())
            );
        }

        if (!isFirstTimeLogin) {
            List<ApiEndpoint> endpoints = new ArrayList<>();
            endpoints.add(new ApiEndpoint("/api/account", "Update personal details and password"));
            endpoints.add(new ApiEndpoint("/api/creditcards", "View all credit cards"));
            response.setAvailableEndpoints(endpoints);
        }

        return response;
    }

    // Fallback for login
    private LoginResponse fallbackForLogin(LoginRequest loginRequest, boolean isFirstTimeLogin, Throwable ex) {
        logger.error("Fallback for login triggered: {}", ex.getMessage());
        LoginResponse fallbackResponse = new LoginResponse();
        fallbackResponse.setToken("fallback-token");
        fallbackResponse.setName(new CustomerEntity.Name("Fallback", "User")); // Using parameterized constructor
        return fallbackResponse;
    }

    // Handle failed login attempts
    private void handleFailedLogin(CustomerEntity customer) {
        int failedAttempts = customer.getFailedAttempts() + 1;
        customer.setFailedAttempts(failedAttempts);
        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            lockAccount(customer);
        }
        customerRepository.save(customer);
    }

    private void lockAccount(CustomerEntity customer) {
        customer.setLocked(true);
        customer.setLockTime(LocalDateTime.now());
        customerRepository.save(customer);
    }

    private void unlockAccountIfEligible(CustomerEntity customer) {
        if (customer.getLockTime() != null &&
                customer.getLockTime().plusHours(LOCK_TIME_DURATION).isBefore(LocalDateTime.now())) {
            resetFailedAttempts(customer);
            customer.setLocked(false);
            customer.setLockTime(null);
            customerRepository.save(customer);
        }
    }

    private void resetFailedAttempts(CustomerEntity customer) {
        customer.setFailedAttempts(0);
        customerRepository.save(customer);
    }

    // Send Verification Email
    public void sendVerificationEmail(String email) {
        logger.info("Sending verification email to: {}", email);

        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
            logger.warn("Customer not found for email: {}", email);
            throw new RuntimeException("Customer not found.");
        }
        if (customer.isAccountValidated()) {
            throw new RuntimeException("Account is already validated.");
        }

        if (customer.getVerificationTokenExpiry() != null && customer.getVerificationTokenExpiry().isAfter(LocalDateTime.now())) {
            throw new RuntimeException("A valid verification token already exists. Check your email.");
        }

        String token = UUID.randomUUID().toString();
        customer.setVerificationToken(token);
        customer.setVerificationTokenExpiry(LocalDateTime.now().plusHours(24));
        customerRepository.save(customer);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setFrom("Teams3_PGP@domain.com");
        message.setSubject("Email Verification");
        message.setText("Click here to verify your account: http://localhost:8081/api/customer/verify?token=" + token);
        mailSender.send(message);
        logger.info("Verification email sent successfully to: {}", email);
    }

    // Verify Account
    public void verifyAccount(String token) {
        logger.info("Attempting to verify account with token: {}", token);

        CustomerEntity customer = customerRepository.findByVerificationToken(token);
        if (customer == null) {
            logger.warn("Invalid verification token: {}", token);
            throw new InvalidTokenException("Invalid verification token.");
        }

        if (customer.getVerificationTokenExpiry() == null || customer.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            logger.warn("Expired verification token: {}", token);
            throw new InvalidTokenException("Verification token has expired.");
        }

        if (customer.isAccountValidated()) {
            logger.info("Account already validated for user: {}", customer.getEmail());
            return;
        }

        customer.setAccountValidated(true);
        customer.setVerificationToken(null);
        customer.setVerificationTokenExpiry(null);
        customerRepository.save(customer);

        logger.info("Account successfully verified for email: {}", customer.getEmail());
    }

    // Password Reset Request
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForRequestPasswordReset")
    public void requestPasswordReset(String email) {
        logger.info("Processing forgot password request for email: {}", email);

        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
            throw new CustomerServiceException("Customer not found.");
        }

        String token = UUID.randomUUID().toString();
        customer.setResetPasswordToken(token);
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1));

        customerRepository.save(customer);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setFrom("Teams3_PGP@domain.com");
        message.setSubject("Forgot Your Password");
        message.setText("Click the link below to reset your password:\n\n" +
                "http://localhost:8081/api/customer/forgot-password/reset-password?token=" + token);
        mailSender.send(message);
        logger.info("Password reset link sent to email: {}", email);
    }

    // Fallback for Password Reset Request
    private void fallbackForRequestPasswordReset(String email, Throwable ex) {
        logger.error("Fallback for password reset triggered: {}", ex.getMessage());
        throw new CustomerServiceException("Service temporarily unavailable. Try again later.");
    }

    // Reset Password
    public void resetPasswordForForgotFlow(String token, String newPassword, String confirmPassword) {
        logger.info("Processing password reset for token: {}", token);

        CustomerEntity customer = customerRepository.findByResetPasswordToken(token);
        if (customer == null || customer.getResetPasswordTokenExpiry() == null ||
                customer.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Invalid or expired reset token.");
        }

        if (!newPassword.equals(confirmPassword)) {
            throw new PasswordMismatchException("New password and confirm password do not match.");
        }

        if (!PasswordValidator.isValid(newPassword)) {
            throw new WeakPasswordException("Password does not meet complexity requirements.");
        }

        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(password -> passwordEncoder.matches(newPassword, password))) {
            throw new CustomerServiceException("New password cannot be one of the last 5 passwords.");
        }

        if (customer.getPasswordHistory() == null) {
            customer.setPasswordHistory(new ArrayList<>());
        }
        customer.getPasswordHistory().add(0, customer.getPassword());
        if (customer.getPasswordHistory().size() > 5) {
            customer.getPasswordHistory().remove(5);
        }

        customer.setPassword(passwordEncoder.encode(newPassword));
        customer.setResetPasswordToken(null);
        customer.setResetPasswordTokenExpiry(null);
        customer.setLocked(false);
        customer.setLockTime(null);

        customerRepository.save(customer);
        logger.info("Password reset successful and account unlocked for email: {}", customer.getEmail());
    }

    // Change Password
    public void changePassword(String currentPassword, String newPassword, String confirmPassword) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Processing change password for user: {}", username);

        CustomerEntity customer = customerRepository.findByUsername(username);
        if (customer == null) {
            throw new CustomerServiceException("Customer not found.");
        }

        if (!passwordEncoder.matches(currentPassword, customer.getPassword())) {
            throw new InvalidPasswordException("Current password is incorrect.");
        }

        if (!newPassword.equals(confirmPassword)) {
            throw new PasswordMismatchException("New password and confirm password do not match.");
        }

        if (!PasswordValidator.isValid(newPassword)) {
            throw new WeakPasswordException("Password does not meet complexity requirements.");
        }

        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(password -> passwordEncoder.matches(newPassword, password))) {
            throw new CustomerServiceException("New password cannot be one of the last 5 passwords.");
        }

        if (customer.getPasswordHistory() == null) {
            customer.setPasswordHistory(new ArrayList<>());
        }
        customer.getPasswordHistory().add(0, customer.getPassword());
        if (customer.getPasswordHistory().size() > 5) {
            customer.getPasswordHistory().remove(5);
        }

        updatePassword(customer, newPassword);
        logger.info("Password changed successfully for user: {}", username);
    }
    
    @CircuitBreaker(name = "customerService", fallbackMethod = "logoutFallback")
    public boolean logout() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Processing logout for user: {}", username);
        if (username == null || username.isEmpty()) {
            throw new CustomerServiceException("No active session found for logout.");
        }
        SecurityContextHolder.clearContext();
        logger.info("User {} logged out successfully at {}", username, LocalDateTime.now());
        return true;
    }

    // Fallback method for logout
    public boolean logoutFallback(Throwable throwable) {
        logger.error("Logout fallback triggered due to: {}", throwable.getMessage());
        return false; // Indicate that logout was unsuccessful
    }

    // Update Password
    public void updatePassword(CustomerEntity customer, String newPassword) {
        customer.setPassword(passwordEncoder.encode(newPassword));
        customer.setPasswordLastUpdated(LocalDateTime.now());
        customer.setPasswordExpiryDate(LocalDateTime.now().plusMonths(6));
        customerRepository.save(customer);
    }
    
}