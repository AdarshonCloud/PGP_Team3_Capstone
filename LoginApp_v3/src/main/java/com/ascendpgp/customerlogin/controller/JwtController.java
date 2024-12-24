package com.ascendpgp.customerlogin.controller;

import com.ascendpgp.customerlogin.utils.JwtService;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/customer/jwt")
public class JwtController {

    private static final Logger logger = LoggerFactory.getLogger(JwtController.class);

    private final JwtService jwtService;

    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Operation(summary = "Validate JWT token")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token is valid"),
        @ApiResponse(responseCode = "400", description = "Invalid token")
    })
    @CircuitBreaker(name = "jwtService", fallbackMethod = "validateTokenFallback")
    @GetMapping("/validate")
    public ResponseEntity<Map<String, String>> validateToken(@RequestParam String token) {
        logger.info("Validating token: {}", token);

        Claims claims = jwtService.extractClaims(token);
        logger.info("Extracted claims: {}", claims);

        Map<String, String> response = new HashMap<>();
        response.put("username", claims.get("username", String.class));
        response.put("email", claims.get("email", String.class)); // Include email in the response

        return ResponseEntity.ok(response);
    }

    /**
     * Fallback method for validateToken.
     * This method will be invoked if the CircuitBreaker is open or an exception occurs in validateToken.
     *
     * @param token The JWT token that was being validated.
     * @param ex    The exception that triggered the fallback.
     * @return A ResponseEntity with a fallback message.
     */
    public ResponseEntity<Map<String, String>> validateTokenFallback(String token, Throwable ex) {
        logger.error("Fallback triggered for token validation. Reason: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(Map.of("error", "Token validation failed due to an error: " + ex.getMessage()));
    }
}