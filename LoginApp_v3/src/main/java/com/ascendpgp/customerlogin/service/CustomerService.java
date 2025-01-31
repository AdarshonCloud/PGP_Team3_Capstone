package com.ascendpgp.customerlogin.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ascendpgp.customerlogin.exception.*;
import com.ascendpgp.customerlogin.model.ApiEndpoint;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.utils.PasswordValidator;
import com.mongodb.MongoSocketWriteException;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;

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

    @Value("${sender.email}")
    private String senderEmail;

    private static final String CUSTOMER_SERVICE = "customerService";
    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final int LOCK_TIME_DURATION = 24;

    // Login method with Circuit Breaker
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForLogin")
    public LoginResponse login(LoginRequest loginRequest, boolean isFirstTimeLogin) {
        logger.info("Login attempt for email: {}", loginRequest.getEmail());

        try {
            CustomerEntity customer = findCustomerByEmail(loginRequest.getEmail());
            validateCustomerAccount(customer);
            validatePassword(loginRequest.getPassword(), customer.getPassword());

            resetFailedAttempts(customer);

            boolean isPasswordExpired = isPasswordExpired(customer);

            if (isFirstTimeLogin) {
                handleFirstTimeLogin(customer);
            }

            String token = jwtService.generateToken(customer.getEmail(), customer.getUsername());
            logger.info("JWT token generated for email: {}", loginRequest.getEmail());

            return prepareLoginResponse(customer, token, isPasswordExpired, isFirstTimeLogin);
        } catch (IllegalArgumentException e) {
            logger.error("Base64 decoding failed for password.");
            throw new InvalidCredentialsException("Invalid email or password.");
        } catch (com.mongodb.MongoTimeoutException | MongoSocketWriteException ex) {
            logger.error("MongoDB connection error.");
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    private CustomerEntity findCustomerByEmail(String email) {
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
            logger.warn("Customer not found for email: {}", email);
            throw new InvalidCredentialsException("Invalid email or password.");
        }
        return customer;
    }

    private void validateCustomerAccount(CustomerEntity customer) {
        if (customer.isLocked()) {
            unlockAccountIfEligible(customer);
            if (customer.isLocked()) {
                throw new AccountLockedException("Account is locked. Please reset your password or wait 24 hours.");
            }
        }
    }

    private void validatePassword(String rawPassword, String hashedPassword) {
        String decodedPassword = new String(Base64.getDecoder().decode(rawPassword));
        if (!passwordEncoder.matches(decodedPassword, hashedPassword)) {
            handleFailedLogin(customer);
            throw new InvalidCredentialsException("Invalid email or password.");
        }
    }

    private boolean isPasswordExpired(CustomerEntity customer) {
        return customer.getPasswordExpiryDate() != null && customer.getPasswordExpiryDate().isBefore(LocalDateTime.now());
    }

    private void handleFirstTimeLogin(CustomerEntity customer) {
        customer.setFirstTimeLogin(false);
        customerRepository.save(customer);
        logger.info("First-time login detected for email: {}. Updated firstTimeLogin to false.", customer.getEmail());
    }

    private LoginResponse prepareLoginResponse(CustomerEntity customer, String token, boolean isPasswordExpired, boolean isFirstTimeLogin) {
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setName(customer.getName());
        response.setAccountValidated(customer.isAccountValidated());
        response.setPasswordExpired(isPasswordExpired);

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
        logger.error("Fallback for login triggered due to: {}", ex.getMessage());

        if (ex instanceof InvalidCredentialsException || ex instanceof AccountLockedException) {
            throw (RuntimeException) ex;
        }

        throw new CustomerServiceException("Service is temporarily unavailable. Please try again later.");
    }

    // Handle failed login attempts
    private void handleFailedLogin(CustomerEntity customer) {
        int failedAttempts = customer.getFailedAttempts() + 1;
        customer.setFailedAttempts(failedAttempts);
        if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
            lockAccount(customer);
            throw new AccountLockedException("Your account has been locked due to multiple failed login attempts.");
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
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "SendVerificationEmailFallback")
    public void sendVerificationEmail(String email) {
        logger.info("Sending verification email to: {}", email);

        try {
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
            message.setFrom(senderEmail);
            message.setSubject("Email Verification");
            message.setText("Click here to verify your account: http://localhost:8081/api/customer/verify?token=" + token);
            mailSender.send(message);
            logger.info("Verification email sent successfully to: {}", email);
        } catch (com.mongodb.MongoTimeoutException | MongoSocketWriteException ex) {
            logger.error("MongoDB connection error.");
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback for Verify Account
    private void SendVerificationEmailFallback(String email, Throwable ex) {
        logger.error("Fallback for sending verification email triggered due to: {}", ex.getMessage());

        if (ex instanceof RuntimeException) {
            throw (RuntimeException) ex;
        }

        throw new CustomerServiceException("Account verification email service is temporarily unavailable. Please try again later.");
    }

    // Verify Account
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForVerifyAccount")
    public void verifyAccount(String token) {
        logger.info("Attempting to verify account with token.");

        try {
            CustomerEntity customer = customerRepository.findByVerificationToken(token);
            if (customer == null) {
                logger.warn("Invalid verification token.");
                throw new InvalidTokenException("Invalid verification token.");
            }

            if (customer.getVerificationTokenExpiry() == null || customer.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
                logger.warn("Expired verification token.");
                throw new InvalidTokenException("Verification token has expired.");
            }

            if (customer.isAccountValidated()) {
                logger.info("Account already validated for user.");
                return;
            }

            customer.setAccountValidated(true);
            customer.setVerificationToken(null);
            customer.setVerificationTokenExpiry(null);
            customerRepository.save(customer);

            logger.info("Account successfully verified.");
        } catch (com.mongodb.MongoTimeoutException | MongoSocketWriteException ex) {
            logger.error("MongoDB connection error.");
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback for Verify Account
    private void fallbackForVerifyAccount(String token, Throwable ex) {
        logger.error("Fallback for account verification triggered due to: {}", ex.getMessage());

        if (ex instanceof InvalidTokenException) {
            throw (InvalidTokenException) ex;
        }

        throw new CustomerServiceException("Account verification service is temporarily unavailable. Please try again later.");
    }

    // Password Reset Request
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForRequestPasswordReset")
    @Retry(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForRequestPasswordReset")
    public void requestPasswordReset(String email) {
        logger.info("Processing forgot password request for email: {}", email);

        try {
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
            message.setFrom(senderEmail);
            message.setSubject("Forgot Your Password");
            message.setText("Click the link below to reset your password:\n\n" +
                    "http://localhost:8081/api/customer/forgot-password/reset-password?token=" + token);
            mailSender.send(message);
            logger.info("Password reset link sent to email: {}", email);
        } catch (com.mongodb.MongoTimeoutException | MongoSocketWriteException ex) {
            logger.error("MongoDB connection error.");
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback for Password Reset Request
    private void fallbackForRequestPasswordReset(String email, Throwable ex) {
        logger.error("Fallback for password reset request triggered due to: {}", ex.getMessage());

        if (ex instanceof RuntimeException) {
            throw (RuntimeException) ex;
        }

        throw new CustomerServiceException("Password reset service is temporarily unavailable. Please try again later.");
    }

    // Reset Password
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForResetPasswordForForgotFlow")
    public void resetPasswordForForgotFlow(String token, String newPassword, String confirmPassword) {
        logger.info("Processing password reset for token.");

        try {
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

            updatePasswordHistory(customer, newPassword);

            customer.setPassword(passwordEncoder.encode(newPassword));
            customer.setResetPasswordToken(null);
            customer.setResetPasswordTokenExpiry(null);
            customer.setLocked(false);
            customer.setLockTime(null);

            customerRepository.save(customer);
            logger.info("Password reset successful and account unlocked.");
        } catch (com.mongodb.MongoTimeoutException | MongoSocketWriteException ex) {
            logger.error("MongoDB connection error.");
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback method for reset password
    private boolean fallbackForResetPasswordForForgotFlow(String token, String newPassword, String confirmPassword, Throwable ex) {
        logger.error("Fallback for reset password (forgot flow) triggered due to: {}", ex.getMessage());

        throw new CustomerServiceException("Reset password flow process is temporarily unavailable. Please try again later.");
    }

    // Change Password
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "ChangePasswordFallback")
    public void changePassword(String currentPassword, String newPassword, String confirmPassword) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Processing change password for user.");

        try {
            CustomerEntity customer = customerRepository.findByUsername(username);
            if (customer == null) {
                throw new CustomerServiceException("Customer not found.");
            }

            if (!passwordEncoder.matches(currentPassword, customer.getPassword())) {
                throw new InvalidCredentialsException("Current password is incorrect.");
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

            updatePasswordHistory(customer, newPassword);
            updatePassword(customer, newPassword);
            logger.info("Password changed successfully for user.");
        } catch (com.mongodb.MongoTimeoutException | MongoSocketWriteException ex) {
            logger.error("MongoDB connection error.");
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback method for change password
    public boolean ChangePasswordFallback(String currentPassword, String newPassword, String confirmPassword, Throwable ex) {
        logger.error("Fallback for change password triggered due to: {}", ex.getMessage());

        throw new CustomerServiceException("Change password service is temporarily unavailable. Please try again later.");
    }

    // Logout
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "logoutFallback")
    public boolean logout(String token) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Processing logout for user.");

        if (username == null || username.isEmpty()) {
            throw new CustomerServiceException("No active session found for logout.");
        }

        jwtService.blacklistToken(token);
        SecurityContextHolder.clearContext();

        logger.info("User logged out successfully and token blacklisted.");
        return true;
    }

    // Fallback method for logout
    public boolean logoutFallback(Throwable ex) {
        logger.error("Fallback for logout triggered due to: {}", ex.getMessage());

        throw new CustomerServiceException("Logout service is temporarily unavailable. Please try again later.");
    }

    // Update Password
    private void updatePassword(CustomerEntity customer, String newPassword) {
        customer.setPassword(passwordEncoder.encode(newPassword));
        customer.setPasswordLastUpdated(LocalDateTime.now());
        customer.setPasswordExpiryDate(LocalDateTime.now().plusMonths(6));
        customerRepository.save(customer);
    }

    // Update Password History
    private void updatePasswordHistory(CustomerEntity customer, String newPassword) {
        if (customer.getPasswordHistory() == null) {
            customer.setPasswordHistory(new ArrayList<>());
        }
        customer.getPasswordHistory().add(0, customer.getPassword());
        if (customer.getPasswordHistory().size() > 5) {
            customer.getPasswordHistory().remove(5);
        }
    }
}
