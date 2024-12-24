package com.ascendpgp.customerlogin.controller;

import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.service.CustomerService;
import com.ascendpgp.customerlogin.dto.ChangePasswordRequest;
import com.ascendpgp.customerlogin.dto.ForgotPasswordRequest;
import com.ascendpgp.customerlogin.dto.ResetPasswordRequest;
import com.ascendpgp.customerlogin.dto.SendVerificationRequest;
import com.ascendpgp.customerlogin.exception.InvalidTokenException;
import com.ascendpgp.customerlogin.model.LoginRequest;
import com.ascendpgp.customerlogin.model.LoginResponse;
import com.ascendpgp.customerlogin.repository.CustomerRepository;
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
import io.swagger.v3.oas.annotations.security.SecurityRequirement;

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

    // First-time login API
    @Operation(summary = "First-time customer login")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful. Returns a JWT token."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid input or missing required fields."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid credentials."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Account is locked or inactive."),
        @ApiResponse(responseCode = "500", description = "Internal server error - Unexpected issues.")
    })
    @PostMapping("/login")
    public ResponseEntity<?> firstTimeLogin(@RequestBody LoginRequest loginRequest) {
        logger.debug("Received first-time login request for email: {}", loginRequest.getEmail());
        try {
            LoginResponse loginResponse = customerService.login(loginRequest, true);

            Map<String, Object> response = new HashMap<>();
            response.put("message", "Welcome " + loginResponse.getName().getFirst() + " " + loginResponse.getName().getLast());
            if (!loginResponse.isAccountValidated()) {
                response.put("note", "Your account is not validated. Please verify your account.");
            }
            response.put("token", loginResponse.getToken());
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            logger.error("Login failed for email: {}. Reason: {}", loginRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", e.getMessage()));
        }
    }

    // Subsequent login API
    @Operation(summary = "Subsequent customer login")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login successful."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid input."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid credentials."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Access denied."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping("/login/subsequent")
    public ResponseEntity<?> subsequentLogin(@RequestBody LoginRequest loginRequest) {
        logger.debug("Received subsequent login request for email: {}", loginRequest.getEmail());
        try {
            LoginResponse loginResponse = customerService.login(loginRequest, false);
            return ResponseEntity.ok(loginResponse);
        } catch (RuntimeException e) {
            logger.error("Subsequent login failed for email: {}. Reason: {}", loginRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", e.getMessage()));
        }
    }

    // Send Verification Email API
    @Operation(summary = "Send verification email")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Verification email sent successfully."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid input."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid credentials."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Action denied."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping("/send-verification")
    public ResponseEntity<?> sendVerification(@RequestBody SendVerificationRequest request) {
        String email = request.getEmail();
        logger.info("Received send-verification request for email: {}", email);
        try {
            customerService.sendVerificationEmail(email);
            return ResponseEntity.ok("Verification link has been sent to your email.");
        } catch (RuntimeException e) {
            logger.error("Failed to send verification email to: {}. Reason: {}", email, e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // Forgot password request API
    @Operation(summary = "Request forgot password")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password reset link sent successfully."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid input."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid credentials."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Action denied."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        String email = request.getEmail();
        logger.info("Processing forgot-password request for email: {}", email);
        try {
            customerService.requestPasswordReset(email);
            return ResponseEntity.ok("Password reset link sent to your email.");
        } catch (RuntimeException e) {
            logger.error("Failed to process forgot password for email: {}. Reason: {}", email, e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // Password reset token validation API
    @Operation(summary = "Validate password reset token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token is valid. Prompt user to reset password."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid or expired token."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Action denied."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @GetMapping("/forgot-password/reset-password")
    public ResponseEntity<?> handleResetPasswordLink(@RequestParam("token") String token) {
        logger.info("Validating password reset token: {}", token);
        try {
            var customer = customerRepository.findByResetPasswordToken(token);
            
            // Check if customer exists and token is valid
            if (customer == null) {
                logger.warn("Password reset token not found: {}", token);
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid token."));
            }

            if (customer.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
                logger.warn("Password reset token expired for customer: {}", customer.getEmail());
                return ResponseEntity.badRequest().body(Map.of("error", "Expired token."));
            }

            // Token is valid
            logger.info("Password reset token is valid for customer: {}", customer.getEmail());
            return ResponseEntity.ok(Map.of(
                "message", "Token is valid. Please provide your new password.",
                "email", customer.getEmail()
            ));
        } catch (Exception e) {
            logger.error("Error validating password reset token: {}", token, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal server error."));
        }
    }
    
    // Password reset API for forgot-password flow
    @Operation(summary = "Reset password")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password reset successfully."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid input."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid token."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Action denied."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping("/forgot-password/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        String token = request.getToken();
        String newPassword = request.getNewPassword();
        String confirmPassword = request.getConfirmPassword();
        logger.info("Processing password reset for token: {}", token);
        try {
            customerService.resetPasswordForForgotFlow(token, newPassword, confirmPassword);
            return ResponseEntity.ok("Password reset successfully.");
        } catch (RuntimeException e) {
            logger.error("Password reset failed for token: {}. Reason: {}", token, e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // Change password API for authenticated user
    @Operation(summary = "Change password")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password changed successfully."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid input."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid current password."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Access denied."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        String currentPassword = request.getCurrentPassword();
        String newPassword = request.getNewPassword();
        String confirmPassword = request.getConfirmPassword();
        logger.info("Processing change-password request.");
        try {
            customerService.changePassword(currentPassword, newPassword, confirmPassword);
            return ResponseEntity.ok("Password changed successfully.");
        } catch (RuntimeException e) {
            logger.error("Change password failed. Reason: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // Account verification API
    @Operation(summary = "Verify account")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Account verified successfully."),
        @ApiResponse(responseCode = "400", description = "Bad request - Invalid or expired token."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid token."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Access denied."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @GetMapping("/verify")
    public ResponseEntity<?> verifyAccount(@RequestParam("token") String token) {
        logger.info("Verifying account with token: {}", token);
        try {
            customerService.verifyAccount(token);
            return ResponseEntity.ok("Account verified successfully.");
        } catch (InvalidTokenException e) {
            logger.error("Verification failed for token: {}. Reason: {}", token, e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
    

    // Logout API
    @Operation(summary = "Logout customer", security = {@SecurityRequirement(name = "bearerAuth")})
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Logout successful."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - User not logged in."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        logger.info("Processing logout request.");
        try {
            boolean isLoggedOut = customerService.logout();
            if (isLoggedOut) {
                return ResponseEntity.ok("Logout successful.");
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No active session found.");
            }
        } catch (RuntimeException e) {
            logger.error("Logout failed. Reason: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", e.getMessage()));
        }
    }
}