package com.ascendpgp.customerlogin.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.ascendpgp.customerlogin.model.BlacklistedToken;
import com.ascendpgp.customerlogin.repository.BlacklistedTokenRepository;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final Key SECRET_KEY;
    private final BlacklistedTokenRepository blacklistedTokenRepository;

    public JwtService(
            @Value("${jwt.secret}") String secretKey,
            BlacklistedTokenRepository blacklistedTokenRepository
        ) {if (secretKey == null || secretKey.length() < 32) {
            logger.error("Invalid secret key. It must be at least 32 characters long.");
            throw new IllegalArgumentException("Secret key must be at least 32 characters long.");
        }
        this.SECRET_KEY = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.blacklistedTokenRepository = blacklistedTokenRepository;
        logger.info("JWT Service initialized successfully with a secure secret key.");
    }

    /**
     * Blacklist a token.
     *
     * @param token Token to blacklist
     */
    public void blacklistToken(String token) {
        // Extract claims to fetch the expiry date
        Claims claims = extractClaims(token);
        Date expiryDate = claims.getExpiration();

        // Save the token to the blacklist
        BlacklistedToken blacklistedToken = new BlacklistedToken(token, expiryDate);
        blacklistedTokenRepository.save(blacklistedToken);
        logger.info("Token blacklisted successfully: {}", token);
    }
    
    /**
     * Check if a token is blacklisted.
     *
     * @param token Token to check
     * @return True if blacklisted, otherwise false
     */
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokenRepository.existsByToken(token);
    }

    /**
     * Generate a JWT token with email and username as claims.
     *
     * @param email    User's email (used as the token subject)
     * @param username User's username
     * @return JWT token as a String
     */
    public String generateToken(String email, String username) {
        logger.info("Generating token for email: {} and username: {}", email, username);
        String token = Jwts.builder()
                .setSubject(email) // Email is the subject of the token
                .claim("email", email) // Add email as a claim
                .claim("username", username) // Add username as a claim
                .setIssuedAt(new Date()) // Current date as issue time
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10-hour expiration
                .signWith(SECRET_KEY) // Sign the token with the secret key
                .compact();
        logger.info("JWT token generated successfully.");
        return token;
    }

    /**
     * Extract all claims from a JWT token.
     *
     * @param token JWT token
     * @return Claims extracted from the token
     */
    public Claims extractClaims(String token) {
        logger.debug("Extracting claims from token.");
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Extract username from a JWT token.
     *
     * @param token JWT token
     * @return Username as a String
     */
    public String extractUsername(String token) {
        String username = extractClaims(token).get("username", String.class);
        logger.debug("Extracted username: {}", username);
        return username;
    }

    /**
     * Extract email from a JWT token.
     *
     * @param token JWT token
     * @return Email as a String
     */
    public String extractEmail(String token) {
        String email = extractClaims(token).get("email", String.class);
        logger.debug("Extracted email: {}", email);
        return email;
    }

    /**
     * Extract username and email from the token.
     *
     * @param token JWT token
     * @return Map containing "username" and "email" keys with their values
     */
    public Map<String, String> extractUserDetails(String token) {
        Claims claims = extractClaims(token);
        Map<String, String> userDetails = new HashMap<>();
        userDetails.put("username", claims.get("username", String.class));
        userDetails.put("email", claims.get("email", String.class));
        logger.debug("Extracted user details: {}", userDetails);
        return userDetails;
    }

    /**
     * Validate the token's signature and expiration.
     *
     * @param token JWT token
     * @return True if the token is valid, otherwise false
     */
    public boolean validateToken(String token) {
    	
    	// Check if the token is blacklisted
        if (isTokenBlacklisted(token)) {
            logger.warn("Token is blacklisted: {}", token);
            return false;
        }
        
        try {
            Claims claims = extractClaims(token);
            logger.info("Token is valid. Claims: {}", claims);
            return true;
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validate the token and extract claims.
     *
     * @param token JWT token
     * @return Claims if the token is valid
     * @throws RuntimeException if the token is invalid
     */
    public Claims validateAndExtractClaims(String token) {
        logger.info("Validating and extracting claims for token.");
        if (validateToken(token)) {
            Claims claims = extractClaims(token);
            logger.info("Token validated successfully. Extracted claims: {}", claims);
            return claims;
        } else {
            logger.error("Token is invalid or expired.");
            throw new RuntimeException("Invalid or expired token.");
        }
    }
}