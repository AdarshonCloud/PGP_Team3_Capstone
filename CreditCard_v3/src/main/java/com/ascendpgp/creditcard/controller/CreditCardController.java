package com.ascendpgp.creditcard.controller;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import com.ascendpgp.creditcard.exception.CardAlreadyDeletedException;
import com.ascendpgp.creditcard.exception.CardNotFoundException;
import com.ascendpgp.creditcard.exception.InvalidOtpException;
import com.ascendpgp.creditcard.model.CreditCard;
import com.ascendpgp.creditcard.model.CreditCard.CardDetails;
import com.ascendpgp.creditcard.model.CreditCardRequest;
import com.ascendpgp.creditcard.service.CreditCardService;
import com.ascendpgp.creditcard.service.FallbackService;
import com.ascendpgp.creditcard.utils.JwtService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/customer/creditcard")
public class CreditCardController {

    private static final Logger logger = LoggerFactory.getLogger(CreditCardController.class);

    @Autowired
    private CreditCardService creditCardService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private FallbackService fallbackService;

    @Operation(summary = "Add a new credit card")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Credit card added successfully."),
            @ApiResponse(responseCode = "400", description = "Invalid input or validation error."),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token."),
            @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping
    public ResponseEntity<String> addCreditCard(@RequestHeader("Authorization") String token,
                                                @RequestBody CreditCardRequest request) {
        logger.info("Received request to add credit card with token: {}", maskToken(token));

        Map<String, String> tokenDetails = jwtService.validateAndExtractTokenDetails(token.substring(7));
        String username = tokenDetails.get("username");
        logger.info("Extracted username: {} from token.", username);

        try {
            creditCardService.addCreditCard(username, request);
            return ResponseEntity.ok("Credit card added successfully.");
        } catch (RuntimeException ex) {
            logger.error("Error adding credit card for Username: {}", username, ex);
            if (ex.getMessage().contains("already exists")) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Credit card already exists.");
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
        }
    }

    
    @Operation(summary = "Delete (soft-delete) a credit card using credit card number")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Credit card deleted successfully."),
            @ApiResponse(responseCode = "404", description = "Credit card not found."),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token."),
            @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @DeleteMapping("/{creditCardNumber}")
    public ResponseEntity<?> deleteCreditCard(
            @PathVariable String creditCardNumber,
            HttpServletRequest request) {

        String token = request.getHeader("Authorization");

        if (token == null || !token.startsWith("Bearer ")) {
            logger.warn("Unauthorized access attempt: Missing or invalid token.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid or missing authorization token."));
        }

        // Extract username from the token
        String username = jwtService.extractUsername(token.substring(7));

        try {
            // Perform soft delete and get the masked card number
            String maskedCardNumber = creditCardService.softDeleteCreditCard(username, creditCardNumber);

            // Respond with success message
            String successMessage = String.format("Credit card has been successfully deleted.", maskedCardNumber);
            logger.info("Successfully soft-deleted credit card for Username: {}, CreditCardNumber: {}", username, maskedCardNumber);
            return ResponseEntity.ok(Map.of("message", successMessage));

        } catch (CardNotFoundException ex) {
            logger.error("Credit card not found for Username: {}, CreditCardNumber: {}", username, creditCardNumber, ex);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", ex.getMessage()));

        } catch (CardAlreadyDeletedException ex) {
            logger.error("Attempt to delete an already deleted card for Username: {}, CreditCardNumber: {}", username, creditCardNumber, ex);
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));

        } catch (RuntimeException ex) {
            logger.error("Unexpected error during deletion for Username: {}, CreditCardNumber: {}", username, creditCardNumber, ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "An unexpected error occurred. Please try again later."));
        }
    }
    
    @PutMapping("/{creditCardNumber}/toggle")
    public ResponseEntity<String> toggleCreditCard(
            @PathVariable String creditCardNumber,
            HttpServletRequest request) {

        String token = request.getHeader("Authorization");

        if (token == null || !token.startsWith("Bearer ")) {
            logger.warn("Unauthorized access attempt: Missing or invalid token.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String username = jwtService.extractUsername(token.substring(7));

        try {
            // Attempt to toggle the credit card status
            CreditCard.CardDetails updatedCardDetails = creditCardService.toggleCreditCardStatus(username, creditCardNumber);

            // Build the response message based on the new status
            String responseMessage = String.format(
                "The credit card status was successfully %s.",
                updatedCardDetails.getStatus()
            );

            logger.info("Successfully toggled credit card for Username: {}, CreditCardNumber: {}", username, creditCardNumber);

            return ResponseEntity.ok(responseMessage);

        } catch (CardNotFoundException ex) {
            logger.error("Card not found for Username: {}, CreditCardNumber: {}", username, creditCardNumber, ex);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Credit card not found.");

        } catch (RuntimeException ex) {
            logger.error("Error toggling credit card for Username: {}, CreditCardNumber: {}", username, creditCardNumber, ex);

            // Handle soft-deleted cards specifically
            if (ex.getMessage().contains("soft-deleted")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Card is marked deleted and cannot be toggled.");
            }

            // Fallback for other unexpected errors
            fallbackService.toggleCreditCardFallback(username, creditCardNumber, ex);

            // Return a generic error response
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred. Please try again later.");
        }
    }
    

    @Operation(summary = "Get all active (non-deleted) credit cards for a user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successfully retrieved active credit cards."),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token."),
            @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @GetMapping
    public ResponseEntity<?> getActiveCreditCards(@RequestHeader("Authorization") String token) {
        logger.info("Received request to fetch active credit cards with token: {}", maskToken(token));
        try {
            Map<String, String> tokenDetails = jwtService.validateAndExtractTokenDetails(token.substring(7));
            String username = tokenDetails.get("username");
            logger.info("Extracted username: {} from token.", username);

            List<CardDetails> creditCards = creditCardService.getActiveCreditCards(username);
            logger.info("Returning {} active credit cards for user: {}", creditCards.size(), username);

            return ResponseEntity.ok(creditCards);
        } catch (Exception e) {
            logger.error("Error fetching active credit cards: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("{\"error\": \"Internal Server Error\"}");
        }
    }
    
    /**
     * Endpoint to generate OTP for full credit card details.
     */
    @Operation(summary = "Generate OTP and send to registerd email to unmask Credit Card Details", security = {@SecurityRequirement(name = "bearerAuth")})
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "OTP sent successfully."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token."),
        @ApiResponse(responseCode = "403", description = "Forbidden - Access denied to fetch user email."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @PostMapping("/generate-otp")
    public ResponseEntity<String> generateOtp(@RequestHeader("Authorization") String token) {
        logger.info("Received request to generate OTP.");

        try {
            String username = jwtService.extractUsername(token.substring(7));
            String email = creditCardService.getUserEmail(username, token.substring(7)); // Fetch user's email
            creditCardService.generateOtp(email);
            return ResponseEntity.ok("OTP sent to your registered email.");
        } catch (HttpClientErrorException.Forbidden e) {
            logger.warn("Access forbidden while generating OTP: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied while fetching user email.");
        } catch (Exception e) {
            logger.error("Error generating OTP: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to generate OTP.");
        }
    }
    
    /**
     * Endpoint to fetch full credit card details after OTP validation.
     */
    @Operation(summary = "Fetch full credit card details after OTP validation")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Full credit card details fetched successfully."),
        @ApiResponse(responseCode = "400", description = "Invalid input or OTP validation error."),
        @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid or missing token."),
        @ApiResponse(responseCode = "404", description = "Credit card not found."),
        @ApiResponse(responseCode = "500", description = "Internal server error.")
    })
    @GetMapping("/full-details")
    public ResponseEntity<CardDetails> getFullCreditCardDetails(
            @RequestHeader("Authorization") String token,
            @RequestParam String username,
            @RequestParam String cardNumber,
            @RequestParam String otp) {
        logger.info("Fetching full credit card details for user: {}", username);

        try {
            String jwtToken = token.substring(7); // Remove "Bearer " prefix
            CardDetails cardDetails = creditCardService.getFullCreditCardDetails(username, cardNumber, otp, jwtToken);
            return ResponseEntity.ok(cardDetails);
        } catch (InvalidOtpException e) {
            logger.warn("Invalid or expired OTP for user: {}", username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        } catch (CardNotFoundException e) {
            logger.warn("Credit card not found for user: {}", username);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        } catch (Exception e) {
            logger.error("Error fetching full credit card details for user: {}. Error: {}", username, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    private String maskToken(String token) {
        if (token != null && token.length() > 10) {
            return token.substring(0, 6) + "******" + token.substring(token.length() - 4);
        }
        return "******";
    }
}