package com.ascendpgp.customerlogin.controller;

import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.Service.CustomerService;
import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.model.LoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/customer")
public class CustomerController {
	
	private static final Logger logger = LoggerFactory.getLogger(CustomerController.class);
	 
    @Autowired
    private CustomerRepository customerRepository;
    
    @Autowired
    private CustomerService customerService;

    // Login API
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");

	 // Redact sensitive fields for logging
    	Map<String, String> sanitizedRequest = new HashMap<>(request);
    	sanitizedRequest.put("password", "********"); // Mask the password
    	System.out.println("Received login request: " + sanitizedRequest);
	    
        logger.info("Received login request for email: {}", email);
        
        try {
            // Call the service to handle login
            LoginResponse loginResponse = customerService.login(email, password);

            // Prepare response map
            Map<String, Object> response = new HashMap<>();
            String message = "Welcome " + loginResponse.getLastName() + " | " + loginResponse.getFirstName() + "!";
            if (!loginResponse.isAccountValidated()) {
                message += " Your account is not yet verified. Please verify your account to unlock full features.";
            }
            response.put("message", message);
            response.put("token", loginResponse.getToken());
            response.put("verificationAction", "/api/customer/send-verification");
            
            logger.info("Login successful for email: {}", email);
            return ResponseEntity.ok(response); // Return JSON response with token

        } catch (RuntimeException e) {
        	logger.error("Login failed for email: {}. Reason: {}", email, e.getMessage());
            // Handle known exceptions
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
        	logger.error("Unexpected error during login for email: {}", email, e);
            // Handle unexpected exceptions
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "An unexpected error occurred."));
        }
    }


    // Send Verification Email API
    @PostMapping("/send-verification")
    public ResponseEntity<?> sendVerification(@RequestBody Map<String, String> request) {
    	String email = request.get("email");
    	logger.info("Received send-verification request for email: {}", email);
        try {
            customerService.sendVerificationEmail(email);
            logger.info("Verification email sent successfully to: {}", email);
            return ResponseEntity.ok("Verification link has been sent to your email.");
        } catch (RuntimeException e) {
        	logger.error("Failed to send verification email to: {}. Reason: {}", email, e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

 // API to verify the account
    @GetMapping("/verify")
    public ResponseEntity<?> verifyAccount(@RequestParam("token") String token) {
    	logger.info("Received verify-account request with token: {}", token);
        try {
            customerService.verifyAccount(token);
            logger.info("Account successfully verified for token: {}", token);
            return ResponseEntity.ok("Account successfully verified. You can now log in.");
        } catch (InvalidTokenException e) {
        	logger.error("Verification failed for token: {}. Reason: {}", token, e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
        	logger.error("Verification failed for token: {}. Reason: {}", token, e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(500).body("An unexpected error occurred.");
        }
    }


    // Forgot Password API
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        logger.info("Forgot password request received for email: {}", email);
        try {
            customerService.requestPasswordReset(email);
            return ResponseEntity.ok("Password reset link has been sent to your email.");
        } catch (RuntimeException e) {
        	logger.error("Failed to process forgot password for email: {}. Reason: {}", email, e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    
    @GetMapping("/forgot-password/reset-password")
    public ResponseEntity<?> handleResetPasswordLink(@RequestParam("token") String token) {
        // Verify the token exists and is valid
        CustomerEntity customer = customerRepository.findByResetPasswordToken(token);
        if (customer == null || customer.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body("Invalid or expired token.");
        }

        // Optionally, return a custom response or redirect to a front-end page
        return ResponseEntity.ok("Token is valid. Please provide your new password.");
    }

    // Password reset API for Forgot Password 
    @PostMapping("/forgot-password/reset-password")
    public ResponseEntity<?> resetPasswordForForgotPassword(@RequestBody Map<String, String> request) {
        
            String token = request.get("token");
            String newPassword = request.get("newPassword");
            String confirmPassword = request.get("confirmPassword");
            logger.info("Password reset request received for token: {}", token);
            
          try {
            customerService.resetPasswordForForgotFlow(token, newPassword, confirmPassword);
            return ResponseEntity.ok("Password has been reset successfully.");
        } catch (RuntimeException e) {
        	logger.error("Failed to reset password for token: {}. Reason: {}", token, e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


    // Reset Password API when User knows the password
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request) {
        
            String currentPassword = request.get("currentPassword");
            String newPassword = request.get("newPassword");
            String confirmPassword = request.get("confirmPassword");
            logger.info("Change password request received.");
          try {
            	
            if (currentPassword == null || newPassword == null || confirmPassword == null) 
            	{
                throw new IllegalArgumentException("All fields are required.");
            	}

            customerService.changePassword(currentPassword, newPassword, confirmPassword);
            logger.info("Password was updated successfully via change-password");
            
            return ResponseEntity.ok("Password has been changed successfully.");
            } 
          catch (RuntimeException e) {
        	logger.error("Failed to change password. Reason: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

}
