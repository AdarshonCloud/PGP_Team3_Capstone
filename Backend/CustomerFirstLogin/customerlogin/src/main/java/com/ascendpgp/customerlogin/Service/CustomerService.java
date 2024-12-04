package com.ascendpgp.customerlogin.Service;

import com.ascendpgp.customerlogin.exception.CustomerServiceException;
import com.ascendpgp.customerlogin.exception.InvalidPasswordException;
import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.exception.PasswordMismatchException;
import com.ascendpgp.customerlogin.exception.WeakPasswordException;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.PasswordValidator;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.model.LoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.UUID;

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

    public boolean validatePassword(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword, hashedPassword);
    }
    
    public LoginResponse login(String email, String rawPassword) {
    	logger.info("Login attempt for email: {}", email);
        // Find customer by email
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
        	logger.warn("Customer not found for email: {}", email);
            throw new CustomerServiceException("Invalid email or password.");
        }

        // Validate password
        if (!passwordEncoder.matches(rawPassword, customer.getPassword())) {
        	logger.warn("Invalid password attempt for email: {}", email);
            throw new CustomerServiceException("Invalid email or password.");
        }
        
        
        // Determine account validation status
        boolean isAccountValidated = customer.isAccountValidated();
        
        if (!isAccountValidated) {
            logger.info("Account not validated for email: {}", email);
        }

        // Update firstTimeLogin to false after the first successful login
        if (customer.isFirstTimeLogin()) {
            customer.setFirstTimeLogin(false);
            customerRepository.save(customer); // Save changes
            logger.info("First-time login detected for email: {}. Updated firstTimeLogin to false.", email);
        }
        

        // Generate JWT token
        String token = jwtService.generateToken(email);
        logger.info("JWT token generated for email: {}", email);

        // Prepare and return login response
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setFirstName(customer.getFirstName());
        response.setLastName(customer.getLastName());
        response.setAccountValidated(isAccountValidated);

        return response;
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

        // Reuse existing token if valid
        if (customer.getVerificationTokenExpiry() != null && customer.getVerificationTokenExpiry().isAfter(LocalDateTime.now())) {
            throw new RuntimeException("A valid verification token already exists. Check your email.");
        }

        String token = UUID.randomUUID().toString();
        customer.setVerificationToken(token);
        customer.setVerificationTokenExpiry(LocalDateTime.now().plusHours(24));
        customerRepository.save(customer);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setFrom("Teams3_PGP@walmart.com");
        message.setSubject("Email Verification");
        message.setText("Click here to verify your account: http://localhost:8081/api/customer/verify?token=" + token);
        mailSender.send(message);
        logger.info("Verification email sent successfully to: {}", email);
    }

    
    public void verifyAccount(String token) {
    	logger.info("Attempting to verify account with token: {}", token);
        // Fetch the customer by the verification token
        CustomerEntity customer = customerRepository.findByVerificationToken(token);
        if (customer == null) {
        	logger.warn("Invalid verification token: {}", token);
            throw new InvalidTokenException("Invalid verification token.");
        }

        // Check if the token has expired
        if (customer.getVerificationTokenExpiry() == null || customer.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
        	logger.warn("Expired verification token: {}", token);
        	throw new InvalidTokenException("Verification token has expired.");
        }

        // If the account is already validated, provide a meaningful message
        if (customer.isAccountValidated()) {
            System.out.println("Account is already validated for user: " + customer.getEmail());
            return; // Optional: Could throw an exception if preferred
        }

        // Validate the account and clear token details
        customer.setAccountValidated(true);
        customer.setVerificationToken(null);
        customer.setVerificationTokenExpiry(null);
        customerRepository.save(customer);

        System.out.println("Account successfully verified for user: " + customer.getEmail());
        logger.info("Account successfully verified for email: {}", customer.getEmail());
    }




    // Forgot Password
    public void requestPasswordReset(String email) {
    	
    	logger.info("Processing forgot password request for email: {}", email);

        // Find the customer by email
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
        	logger.warn("Customer not found for email: {}", email);
            throw new RuntimeException("Customer not found");
        }

        // Generate reset token and expiry
        String token = UUID.randomUUID().toString();
        customer.setResetPasswordToken(token);
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1)); // Token valid for 1 hour

        // Save the reset token to the database
        customerRepository.save(customer);

        // Send email with the reset link
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setFrom("Teams3_PGP@walmart.com");
        message.setSubject("Forgot Your Password");
        message.setText("Click the link below to reset your password:\n\n" +
            "http://localhost:8081/api/customer/forgot-password/reset-password?token=" + token);
        mailSender.send(message);
        logger.info("Password reset link sent to email: {}", email);
    }
    

    // Password reset when User clicks on Forgot Password
    public void resetPasswordForForgotFlow(String token, String newPassword, String confirmPassword) {
    	 logger.info("Processing password reset for token: {}", token);
        // Validate token and find user
        CustomerEntity customer = customerRepository.findByResetPasswordToken(token);
        if (customer == null || customer.getResetPasswordTokenExpiry() == null || customer.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
        	logger.warn("Invalid or expired reset token: {}", token);
            throw new InvalidTokenException("Invalid or expired reset token.");
        }

        // Validate new password matches confirmation
        if (!newPassword.equals(confirmPassword)) {
        	logger.warn("Password mismatch for token: {}", token);
            throw new RuntimeException("New password and confirm password do not match.");
        }

        // Validate password complexity
        if (!PasswordValidator.isValid(newPassword)) {
        	logger.warn("Weak password provided during reset for token: {}", token);
            throw new RuntimeException("Password does not meet complexity requirements.");
        }

        // Prevent reuse of recent passwords
        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(hashedPassword -> passwordEncoder.matches(newPassword, hashedPassword))) {
        	logger.warn("Password reuse attempt for token: {}", token);
            throw new RuntimeException("New password cannot be one of the last 5 passwords.");
        }

        // Update password history
        if (customer.getPasswordHistory() == null) {
            customer.setPasswordHistory(new ArrayList<>());
        }
        customer.getPasswordHistory().add(0, customer.getPassword()); // Add current password to history
        if (customer.getPasswordHistory().size() > 5) {
            customer.getPasswordHistory().remove(5); // Keep only the last 5 passwords
        }

        // Hash and save new password
        customer.setPassword(passwordEncoder.encode(newPassword));

        // Clear reset token and expiry
        customer.setResetPasswordToken(null);
        customer.setResetPasswordTokenExpiry(null);

        // Save updated user
        customerRepository.save(customer);
        logger.info("Password successfully reset for token: {}", token);
    }



    // Reset Password Logic when the user knows the current password
    public void changePassword(String currentPassword, String newPassword, String confirmPassword) {
        // Assume authenticated user's username is retrieved via security context
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Processing change password for user: {}", username);
        
        CustomerEntity customer = customerRepository.findByUsername(username);
        if (customer == null) {
        	logger.warn("Customer not found for username: {}", username);
            throw new RuntimeException("Customer not found");
        }

        // Validate current password
        if (!passwordEncoder.matches(currentPassword, customer.getPassword())) {
        	logger.warn("Invalid current password for username: {}", username);
            throw new InvalidPasswordException("Current password is incorrect.");
        }

        // Validate new password and confirmation match
        if (!newPassword.equals(confirmPassword)) {
        	logger.warn("Password mismatch for username: {}", username);
            throw new PasswordMismatchException("New password and confirm password do not match.");
        }

        // Validate password complexity
        if (!PasswordValidator.isValid(newPassword)) {
        	logger.warn("Weak password provided by username: {}", username);
            throw new WeakPasswordException("Password does not meet complexity requirements.");
        }

        // Prevent reuse of recent passwords
        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(hashedPassword -> passwordEncoder.matches(newPassword, hashedPassword))) {
        	logger.warn("Password reuse attempt by username: {}", username);
            throw new RuntimeException("New password cannot be one of the last 5 passwords.");
        }

        // Update password history
        if (customer.getPasswordHistory() == null) {
            customer.setPasswordHistory(new ArrayList<>());
        }
        customer.getPasswordHistory().add(0, customer.getPassword()); // Add current password to history
        if (customer.getPasswordHistory().size() > 5) {
            customer.getPasswordHistory().remove(5); // Keep only the last 5 passwords
        }

        // Hash and save new password
        customer.setPassword(passwordEncoder.encode(newPassword));
        customerRepository.save(customer);
        logger.info("Password successfully changed for username: {}", username);
    }
    
}

