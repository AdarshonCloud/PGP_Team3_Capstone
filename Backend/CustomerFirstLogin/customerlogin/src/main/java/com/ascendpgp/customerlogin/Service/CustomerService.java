package com.ascendpgp.customerlogin.Service;

import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.PasswordValidator;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.model.LoginResponse;
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
    
    public LoginResponse login(String email, String rawPassword)  {
        // Find customer by email
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
            throw new RuntimeException("Invalid email or password.");
        }

        // Validate password
        if (!passwordEncoder.matches(rawPassword, customer.getPassword())) {
            throw new RuntimeException("Invalid email or password.");
        }

        // Validate password complexity (for reset/change password)
        if (!PasswordValidator.isValid(rawPassword)) {
            throw new RuntimeException("Password does not meet complexity requirements.");
        }

        // Check account validation
        if (!customer.isAccountValidated()) {
            System.out.println("Welcome! Congratulations on successful registration. Please verify your account to unlock full features.");
        } else {
            System.out.println("Welcome back, " + customer.getFirstName() + " " + customer.getLastName() + "!");
        }

        // Update firstTimeLogin to false if it's true
        if (customer.isFirstTimeLogin()) {
            customer.setFirstTimeLogin(false);
            customerRepository.save(customer); // Save changes
            System.out.println("First-time login detected. Updated firstTimeLogin to false.");
            
        }
        
        System.out.println("Login successful for user: " + email);
        // Generate and return JWT token
        String token = jwtService.generateToken(email);
        
     // Prepare the response
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setFirstName(customer.getFirstName());
        response.setLastName(customer.getLastName());
        response.setAccountValidated(customer.isAccountValidated());

        return response;
    }          
    


    // Send Verification Email
    public void sendVerificationEmail(String email) {
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
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
    }

    
    // Verify Account
    public void verifyAccount(String token) {
        CustomerEntity customer = customerRepository.findByVerificationToken(token);
        if (customer == null || customer.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Invalid or expired verification token.");
        }
        
        if (customer.getVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Verification token has expired.");
        }
        if (customer.isAccountValidated()) {
            throw new RuntimeException("Account is already validated.");
        }

        customer.setAccountValidated(true);
        customer.setVerificationToken(null);
        customer.setVerificationTokenExpiry(null);
        customerRepository.save(customer);
        
        System.out.println("Account verified for user: " + customer.getEmail());
    }



    // Forgot Password
    public void requestPasswordReset(String email) {
        // Find the customer by email
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
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
    }
    

    // Password reset when User clicks on Forgot Password
    public void resetPasswordForForgotFlow(String token, String newPassword, String confirmPassword) {
        // Validate token and find user
        CustomerEntity customer = customerRepository.findByResetPasswordToken(token);
        if (customer == null || customer.getResetPasswordTokenExpiry() == null || customer.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Invalid or expired reset token.");
        }

        // Validate new password matches confirmation
        if (!newPassword.equals(confirmPassword)) {
            throw new RuntimeException("New password and confirm password do not match.");
        }

        // Validate password complexity
        if (!PasswordValidator.isValid(newPassword)) {
            throw new RuntimeException("Password does not meet complexity requirements.");
        }

        // Prevent reuse of recent passwords
        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(hashedPassword -> passwordEncoder.matches(newPassword, hashedPassword))) {
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
    }



    // Reset Password Logic When user knows the current password
    public void changePassword(String currentPassword, String newPassword, String confirmPassword) {
        // Assume authenticated user's username is retrieved via security context
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        CustomerEntity customer = customerRepository.findByUsername(username);
        if (customer == null) {
            throw new RuntimeException("Customer not found");
        }

        // Validate current password
        if (!passwordEncoder.matches(currentPassword, customer.getPassword())) {
            throw new RuntimeException("Current password is incorrect.");
        }

        // Validate new password and confirmation match
        if (!newPassword.equals(confirmPassword)) {
            throw new RuntimeException("New password and confirm password do not match.");
        }

        // Validate password complexity
        if (!PasswordValidator.isValid(newPassword)) {
            throw new RuntimeException("Password does not meet complexity requirements.");
        }

        // Prevent reuse of recent passwords
        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(hashedPassword -> passwordEncoder.matches(newPassword, hashedPassword))) {
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
    }

}

