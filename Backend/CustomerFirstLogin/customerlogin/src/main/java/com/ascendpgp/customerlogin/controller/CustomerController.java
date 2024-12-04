package com.ascendpgp.customerlogin.controller;

import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.Service.CustomerService;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.model.LoginResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.SubsequentLoginErrorResponse;
import com.ascendpgp.customerlogin.utils.JwtService;

@RestController
@RequestMapping("/api/customer")
public class CustomerController {
	
	
    @Autowired
    private CustomerRepository customerRepository;
    
    @Autowired
    private CustomerService customerService;

    @Autowired
    private JwtService jwtService;  // Add this line

    // Login API
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String password = request.get("password");

        try {
            
            // Call the service to handle login
            LoginResponse loginResponse = customerService.login(email, password);

            // Return response with the token
            Map<String, Object> response = new HashMap<>();
            String message = "Welcome " + loginResponse.getLastName() + " | " + loginResponse.getFirstName() + "! " ;
            response.put(message, " Please verify your account to unlock full features.");
            response.put("token", loginResponse.getToken());

            return ResponseEntity.ok(response); // Return JSON response with token

        } catch (RuntimeException e) {
            // Return appropriate error message
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            // Log and return a generic error message for unexpected exceptions
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "An unexpected error occurred."));
        }
    }

    public LoginResponse handleSubsequentLogin(LoginRequest loginRequest) {
        System.out.println("Attempting subsequent login for email: " + loginRequest.getUsername());

        CustomerEntity customer = customerRepository.findByEmail(loginRequest.getUsername());
        System.out.println("Found customer in DB: " + (customer != null));

        if (customer != null) {
            System.out.println("Stored password: " + customer.getPassword());
            System.out.println("Input password: " + loginRequest.getPassword());
        }

        if (customer == null) {
            throw new RuntimeException("Invalid username or password.");
        }

        // Temporarily bypass password encoding for testing
        if (!loginRequest.getPassword().equals(customer.getPassword())) {
            throw new RuntimeException("Invalid username or password.");
        }

        // Rest of your existing code...
        String token = jwtService.generateToken(customer.getEmail());

        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setFirstName(customer.getFirstName());
        response.setLastName(customer.getLastName());
        response.setAccountValidated(customer.isAccountValidated());

        return response;
    }

    @PostMapping("/login/subsequent")
    public ResponseEntity<?> subsequentLogin(@RequestBody LoginRequest loginRequest) {
        try {
            System.out.println("Received login request with username: " + loginRequest.getUsername());
            LoginResponse response = customerService.handleSubsequentLogin(loginRequest);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new SubsequentLoginErrorResponse(e.getMessage(), "AUTH_ERROR"));
        }
    }


    // Send Verification Email API
    @PostMapping("/send-verification")
    public ResponseEntity<?> sendVerification(@RequestBody Map<String, String> emailData) {
        try {
            customerService.sendVerificationEmail(emailData.get("email"));
            return ResponseEntity.ok("Verification link has been sent to your email.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

 // API to verify the account
    @GetMapping("/verify")
    public ResponseEntity<?> verifyAccount(@RequestParam("token") String token) {
        try {
            customerService.verifyAccount(token);
            return ResponseEntity.ok("Account successfully verified. You can now log in.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("An unexpected error occurred.");
        }
    }


    // Forgot Password API
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            customerService.requestPasswordReset(email);
            return ResponseEntity.ok("Password reset link has been sent to your email.");
        } catch (RuntimeException e) {
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
        try {
            String token = request.get("token");
            String newPassword = request.get("newPassword");
            String confirmPassword = request.get("confirmPassword");

            customerService.resetPasswordForForgotFlow(token, newPassword, confirmPassword);
            return ResponseEntity.ok("Password has been reset successfully.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


    // Reset Password API when User knows the password
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> request) {
        try {
            String currentPassword = request.get("currentPassword");
            String newPassword = request.get("newPassword");
            String confirmPassword = request.get("confirmPassword");

            customerService.changePassword(currentPassword, newPassword, confirmPassword);
            return ResponseEntity.ok("Password has been changed successfully.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
