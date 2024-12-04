package com.ascendpgp.customerlogin.Service;

import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.utils.PasswordValidator;
import com.ascendpgp.customerlogin.utils.JwtService;
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

    public LoginResponse login(String email, String rawPassword) {
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
            throw new RuntimeException("Invalid email or password.");
        }

        if (!passwordEncoder.matches(rawPassword, customer.getPassword())) {
            throw new RuntimeException("Invalid email or password.");
        }

        if (!PasswordValidator.isValid(rawPassword)) {
            throw new RuntimeException("Password does not meet complexity requirements.");
        }

        if (!customer.isAccountValidated()) {
            System.out.println("Welcome! Congratulations on successful registration. Please verify your account to unlock full features.");
        } else {
            System.out.println("Welcome back, " + customer.getFirstName() + " " + customer.getLastName() + "!");
        }

        if (customer.isFirstTimeLogin()) {
            customer.setFirstTimeLogin(false);
            customerRepository.save(customer);
            System.out.println("First-time login detected. Updated firstTimeLogin to false.");
        }

        System.out.println("Login successful for user: " + email);
        String token = jwtService.generateToken(email);

        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setFirstName(customer.getFirstName());
        response.setLastName(customer.getLastName());
        response.setAccountValidated(customer.isAccountValidated());

        return response;
    }

    public LoginResponse handleSubsequentLogin(LoginRequest loginRequest) {
        try {
            System.out.println("DEBUG: Starting subsequent login process");
            System.out.println("DEBUG: Looking up user: " + loginRequest.getUsername());

            CustomerEntity customer = customerRepository.findByEmail(loginRequest.getUsername());

            System.out.println("DEBUG: Customer found: " + (customer != null));
            if (customer != null) {
                System.out.println("DEBUG: Customer email: " + customer.getEmail());
                System.out.println("DEBUG: Account validated: " + customer.isAccountValidated());
                System.out.println("DEBUG: First time login: " + customer.isFirstTimeLogin());
            }

            if (customer == null) {
                System.out.println("DEBUG: No customer found with email: " + loginRequest.getUsername());
                throw new RuntimeException("Invalid username or password.");
            }

            // Keep existing password comparison for now
            if (!loginRequest.getPassword().equals(customer.getPassword())) {
                System.out.println("DEBUG: Password mismatch");
                throw new RuntimeException("Invalid username or password.");
            }

            if (!customer.isAccountValidated()) {
                System.out.println("DEBUG: Account not validated");
                throw new RuntimeException("Please verify your account first");
            }

            if (customer.isFirstTimeLogin()) {
                System.out.println("DEBUG: First time login detected");
                throw new RuntimeException("Please complete first-time login process");
            }

            System.out.println("DEBUG: Generating JWT token");
            String token = jwtService.generateToken(customer.getEmail());

            LoginResponse response = new LoginResponse();
            response.setToken(token);
            response.setFirstName(customer.getFirstName());
            response.setLastName(customer.getLastName());
            response.setAccountValidated(customer.isAccountValidated());

            System.out.println("DEBUG: Login successful");
            return response;

        } catch (Exception e) {
            System.out.println("DEBUG: Error during login: " + e.getMessage());
            throw e;
        }
    }

    public void sendVerificationEmail(String email) {
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
            throw new RuntimeException("Customer not found.");
        }
        if (customer.isAccountValidated()) {
            throw new RuntimeException("Account is already validated.");
        }

        if (customer.getVerificationTokenExpiry() != null &&
                customer.getVerificationTokenExpiry().isAfter(LocalDateTime.now())) {
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

    public void requestPasswordReset(String email) {
        CustomerEntity customer = customerRepository.findByEmail(email);
        if (customer == null) {
            throw new RuntimeException("Customer not found");
        }

        String token = UUID.randomUUID().toString();
        customer.setResetPasswordToken(token);
        customer.setResetPasswordTokenExpiry(LocalDateTime.now().plusHours(1));
        customerRepository.save(customer);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setFrom("Teams3_PGP@walmart.com");
        message.setSubject("Forgot Your Password");
        message.setText("Click the link below to reset your password:\n\n" +
                "http://localhost:8081/api/customer/forgot-password/reset-password?token=" + token);
        mailSender.send(message);
    }

    public void resetPasswordForForgotFlow(String token, String newPassword, String confirmPassword) {
        CustomerEntity customer = customerRepository.findByResetPasswordToken(token);
        if (customer == null || customer.getResetPasswordTokenExpiry() == null ||
                customer.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Invalid or expired reset token.");
        }

        if (!newPassword.equals(confirmPassword)) {
            throw new RuntimeException("New password and confirm password do not match.");
        }

        if (!PasswordValidator.isValid(newPassword)) {
            throw new RuntimeException("Password does not meet complexity requirements.");
        }

        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(hashedPassword -> passwordEncoder.matches(newPassword, hashedPassword))) {
            throw new RuntimeException("New password cannot be one of the last 5 passwords.");
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
        customerRepository.save(customer);
    }

    public void changePassword(String currentPassword, String newPassword, String confirmPassword) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        CustomerEntity customer = customerRepository.findByEmail(username);
        if (customer == null) {
            throw new RuntimeException("Customer not found");
        }

        if (!passwordEncoder.matches(currentPassword, customer.getPassword())) {
            throw new RuntimeException("Current password is incorrect.");
        }

        if (!newPassword.equals(confirmPassword)) {
            throw new RuntimeException("New password and confirm password do not match.");
        }

        if (!PasswordValidator.isValid(newPassword)) {
            throw new RuntimeException("Password does not meet complexity requirements.");
        }

        if (customer.getPasswordHistory() != null && customer.getPasswordHistory().stream()
                .anyMatch(hashedPassword -> passwordEncoder.matches(newPassword, hashedPassword))) {
            throw new RuntimeException("New password cannot be one of the last 5 passwords.");
        }

        if (customer.getPasswordHistory() == null) {
            customer.setPasswordHistory(new ArrayList<>());
        }
        customer.getPasswordHistory().add(0, customer.getPassword());
        if (customer.getPasswordHistory().size() > 5) {
            customer.getPasswordHistory().remove(5);
        }

        customer.setPassword(passwordEncoder.encode(newPassword));
        customerRepository.save(customer);
    }
}