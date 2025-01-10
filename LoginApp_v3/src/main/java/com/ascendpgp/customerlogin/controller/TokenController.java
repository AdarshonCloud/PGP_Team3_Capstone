package com.ascendpgp.customerlogin.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import com.ascendpgp.customerlogin.repository.BlacklistedTokenRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/customer/token")
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:8083"})
public class TokenController {

	private static final Logger logger = LoggerFactory.getLogger(TokenController.class);

	private final BlacklistedTokenRepository blacklistedTokenRepository;
	private final JwtService jwtService;

	@Autowired
	public TokenController(BlacklistedTokenRepository blacklistedTokenRepository, JwtService jwtService) {
		this.blacklistedTokenRepository = blacklistedTokenRepository;
		this.jwtService = jwtService;
	}

	@Operation(summary = "Validate JWT token")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Token is valid"),
			@ApiResponse(responseCode = "400", description = "Invalid request"),
			@ApiResponse(responseCode = "401", description = "Token is invalid or blacklisted")
	})
	@GetMapping("/validate")
	public ResponseEntity<Map<String, String>> validateToken(@RequestParam("token") String token) {
		logger.info("Token validation request received");
		Map<String, String> response = new HashMap<>();

		try {
			// Check if token is null or empty
			if (token == null || token.trim().isEmpty()) {
				logger.warn("Empty token received");
				response.put("error", "Token cannot be null or empty");
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
			}

			// Check if token is blacklisted
			if (blacklistedTokenRepository.existsByToken(token)) {
				logger.warn("Blacklisted token detected");
				response.put("error", "Token is blacklisted");
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
			}

			// Validate token structure and signature
			if (!jwtService.validateToken(token)) {
				logger.warn("Invalid token structure or signature");
				response.put("error", "Token is invalid");
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
			}

			// Extract and validate claims if needed
			Map<String, String> claims = jwtService.extractUserDetails(token);
			if (claims.isEmpty()) {
				logger.warn("Token claims validation failed");
				response.put("error", "Invalid token claims");
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
			}

			// Token is valid
			logger.info("Token validated successfully");
			response.put("status", "Token is valid");
			response.put("username", claims.get("username"));
			response.put("email", claims.get("email"));
			return ResponseEntity.ok(response);

		} catch (Exception e) {
			logger.error("Token validation failed", e);
			response.put("error", "Token validation failed: " + e.getMessage());
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
		}
	}

	@Operation(summary = "Blacklist JWT token")
	@ApiResponses(value = {
			@ApiResponse(responseCode = "200", description = "Token blacklisted successfully"),
			@ApiResponse(responseCode = "400", description = "Invalid request"),
			@ApiResponse(responseCode = "500", description = "Internal server error")
	})
	@PostMapping("/blacklist")
	public ResponseEntity<Map<String, String>> blacklistToken(@RequestParam("token") String token) {
		logger.info("Token blacklist request received");
		Map<String, String> response = new HashMap<>();

		try {
			if (token == null || token.trim().isEmpty()) {
				logger.warn("Empty token received for blacklisting");
				response.put("error", "Token cannot be null or empty");
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
			}

			jwtService.blacklistToken(token);

			logger.info("Token blacklisted successfully");
			response.put("message", "Token blacklisted successfully");
			return ResponseEntity.ok(response);

		} catch (Exception e) {
			logger.error("Failed to blacklist token", e);
			response.put("error", "Failed to blacklist token: " + e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
		}
	}
}