package com.ascendpgp.customerlogin.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ascendpgp.customerlogin.exception.AccountLockedException;
import com.ascendpgp.customerlogin.exception.CustomerServiceException;
import com.ascendpgp.customerlogin.exception.InvalidCredentialsException;
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

    // Validate password
    public boolean validatePassword(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword, hashedPassword);
    }

    // Login method with Circuit Breaker
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForLogin")
    public LoginResponse login(LoginRequest loginRequest, boolean isFirstTimeLogin) {
        logger.info("Login attempt for email: {}", loginRequest.getEmail());

        try {
            // Find customer by email
            CustomerEntity customer = customerRepository.findByEmail(loginRequest.getEmail());
            if (customer == null) {
                logger.warn("Customer not found for email: {}", loginRequest.getEmail());
                throw new InvalidCredentialsException("Invalid email or password.");
            }

            // Decode Base64-encoded password
            String decodedPassword = new String(Base64.getDecoder().decode(loginRequest.getPassword()));
            logger.info	("Decoded password: {}", decodedPassword);

            // Check if account is locked
            if (customer.isLocked()) {
                unlockAccountIfEligible(customer);
                if (customer.isLocked()) {
                    throw new AccountLockedException("Account is locked. Please reset your password or wait 24 hours.");
                }
            }

            // Validate the decoded password
            if (!passwordEncoder.matches(decodedPassword, customer.getPassword())) {
                handleFailedLogin(customer);
                throw new InvalidCredentialsException("Invalid email or password.");
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
        } catch (IllegalArgumentException e) {
            logger.error("Base64 decoding failed for password: {}", e.getMessage(), e);
            throw new InvalidCredentialsException("Invalid email or password.");
        } catch (com.mongodb.MongoTimeoutException | com.mongodb.MongoSocketWriteException ex) {
            logger.error("MongoDB connection error: {}", ex.getMessage(), ex);
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback for login
    private LoginResponse fallbackForLogin(LoginRequest loginRequest, boolean isFirstTimeLogin, Throwable ex) {
        logger.error("Fallback for login triggered due to: {}", ex.getMessage());

        // Re-throw known business exceptions
        if (ex instanceof InvalidCredentialsException || ex instanceof AccountLockedException) {
            throw (RuntimeException) ex;
        }

        // Handle infrastructure-related issues
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
        }
        catch (com.mongodb.MongoTimeoutException | com.mongodb.MongoSocketWriteException ex) {
            logger.error("MongoDB connection error: {}", ex.getMessage(), ex);
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback for Verify Account
    private void SendVerificationEmailFallback(String email, Throwable ex) {
        logger.error("Fallback for sending verification email triggered due to: {}", ex.getMessage());

        // Re-throw known business exceptions
        if (ex instanceof RuntimeException) {
            throw (RuntimeException) ex;
        }

        // Handle infrastructure-related issues
        throw new CustomerServiceException("Account verification email service is temporarily unavailable. Please try again later.");
    }

    // Verify Account
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForVerifyAccount")
    public void verifyAccount(String token) {
        logger.info("Attempting to verify account with token: {}", token);

        try {
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
        catch (com.mongodb.MongoTimeoutException | com.mongodb.MongoSocketWriteException ex) {
            logger.error("MongoDB connection error: {}", ex.getMessage(), ex);
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback for Verify Account
    private void fallbackForVerifyAccount(String token, Throwable ex) {
        logger.error("Fallback for account verification triggered due to: {}", ex.getMessage());

        // Re-throw known business exceptions
        if (ex instanceof InvalidTokenException) {
            throw (InvalidTokenException) ex;
        }

        // Handle infrastructure-related issues
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
        }
        catch (com.mongodb.MongoTimeoutException | com.mongodb.MongoSocketWriteException ex) {
            logger.error("MongoDB connection error: {}", ex.getMessage(), ex);
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback for Password Reset Request
    private void fallbackForRequestPasswordReset(String email, Throwable ex) {
        logger.error("Fallback for password reset request triggered due to: {}", ex.getMessage());

        // Re-throw known business exceptions
        if (ex instanceof RuntimeException) {
            throw (RuntimeException) ex;
        }

        // Handle infrastructure-related issues
        throw new CustomerServiceException("Password reset service is temporarily unavailable. Please try again later.");
    }

    // Reset Password
    @CircuitBreaker(name = CUSTOMER_SERVICE, fallbackMethod = "fallbackForResetPasswordForForgotFlow")
    public void resetPasswordForForgotFlow(String token, String newPassword, String confirmPassword) {
        logger.info("Processing password reset for token: {}", token);

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
        catch (com.mongodb.MongoTimeoutException | com.mongodb.MongoSocketWriteException ex) {
            logger.error("MongoDB connection error: {}", ex.getMessage(), ex);
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback method for logout
    private boolean fallbackForResetPasswordForForgotFlow(String token, String newPassword, String confirmPassword, Throwable ex) {
        logger.error("Fallback for reset password (forgot flow) triggered due to: {}", ex.getMessage());

        // Handle infrastructure-related issues
        throw new CustomerServiceException("Reset password flow process is temporarily unavailable. Please try again later.");
    }


    // Change Password
    @CircuitBreaker(name = "customerService", fallbackMethod = "ChangePasswordFallback")
    public void changePassword(String currentPassword, String newPassword, String confirmPassword) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Processing change password for user: {}", username);

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
        catch (com.mongodb.MongoTimeoutException | com.mongodb.MongoSocketWriteException ex) {
            logger.error("MongoDB connection error: {}", ex.getMessage(), ex);
            throw new com.ascendpgp.customerlogin.exception.MongoTimeoutException("Connection to the database failed or timed out.");
        }
    }

    // Fallback method for Change Password
    public boolean ChangePasswordFallback(String currentPassword, String newPassword, String confirmPassword, Throwable ex) {
        logger.error("Fallback for change password triggered due to: {}", ex.getMessage());

        // Handle infrastructure-related issues
        throw new CustomerServiceException("Change password service is temporarily unavailable. Please try again later.");
    }

    @CircuitBreaker(name = "customerService", fallbackMethod = "logoutFallback")
    public boolean logout(String token) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Processing logout for user: {}", username);

        if (username == null || username.isEmpty()) {
            throw new CustomerServiceException("No active session found for logout.");
        }

        // Blacklist the token
        jwtService.blacklistToken(token);

        // Clear SecurityContext
        SecurityContextHolder.clearContext();

        logger.info("User {} logged out successfully at {} and token blacklisted.", username, LocalDateTime.now());
        return true;
    }

    // Fallback method for logout
    public boolean logoutFallback(Throwable ex) {
        logger.error("Fallback for logout triggered due to: {}", ex.getMessage());

        // Handle infrastructure-related issues
        throw new CustomerServiceException("Logout service is temporarily unavailable. Please try again later.");
    }

    // Update Password
    public void updatePassword(CustomerEntity customer, String newPassword) {
        customer.setPassword(passwordEncoder.encode(newPassword));
        customer.setPasswordLastUpdated(LocalDateTime.now());
        customer.setPasswordExpiryDate(LocalDateTime.now().plusMonths(6));
        customerRepository.save(customer);
    }

}