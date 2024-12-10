package com.ascendpgp.customerlogin.controller;

import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.Service.CustomerService;
import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.SubsequentLoginErrorResponse;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.utils.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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

    @Autowired
    private JwtService jwtService;

    // Login API
    @Operation(summary = "First-time customer login")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> firstTimeLogin(@RequestBody LoginRequest loginRequest) {
        // Redact sensitive fields for logging
        String sanitizedPassword = "********";
        logger.debug("Received first-time login request: {}", loginRequest.getEmail());

        try {
            logger.info("Processing first-time login for email: {}", loginRequest.getEmail());

            // Call service to handle first-time login
            LoginResponse loginResponse = customerService.login(loginRequest, true);

            // Prepare response map
            Map<String, Object> response = new HashMap<>();
            String message = "Welcome " + loginResponse.getLastName() + " | " + loginResponse.getFirstName() + "!";
            if (!loginResponse.isAccountValidated()) {
                message += " Your account is not yet verified. Please verify your account to unlock full features.";
                response.put("verificationAction", "/api/customer/send-verification");
            }
            response.put("message", message);
            response.put("token", loginResponse.getToken());

            logger.info("First-time login successful for email: {}", loginRequest.getEmail());
            return ResponseEntity.ok(response);

        } catch (RuntimeException e) {
            logger.error("First-time login failed for email: {}. Reason: {}", loginRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(400).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            logger.error("Unexpected error during first-time login for email: {}", loginRequest.getEmail(), e);
            return ResponseEntity.status(500).body(Map.of("error", "An unexpected error occurred."));
        }
    }

    @Operation(summary = "Subsequent customer login")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })

    @PostMapping("/login/subsequent")
    public ResponseEntity<?> subsequentLogin(@RequestBody LoginRequest loginRequest) {
        try {
            logger.debug("Received subsequent login request: {}", loginRequest.getUsername());

            // Handle subsequent login
            // Call service to handle subsequent login
            LoginResponse loginResponse = customerService.login(loginRequest, false);

            logger.info("Subsequent login successful for email: {}", loginRequest.getEmail());
            return ResponseEntity.ok(loginResponse);

        } catch (RuntimeException e) {
            logger.error("Subsequent login failed for email: {}. Reason: {}", loginRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new SubsequentLoginErrorResponse(e.getMessage(), "AUTH_ERROR"));
        } catch (Exception e) {
            logger.error("Unexpected error during subsequent login for email: {}", loginRequest.getEmail(), e);
            return ResponseEntity.status(500)
                    .body(new SubsequentLoginErrorResponse("An unexpected error occurred.", "INTERNAL_ERROR"));
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
