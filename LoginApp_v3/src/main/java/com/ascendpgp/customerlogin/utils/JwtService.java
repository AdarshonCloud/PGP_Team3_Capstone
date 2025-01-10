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

    public JwtService(@Value("${jwt.secret}") String secretKey,
                      BlacklistedTokenRepository blacklistedTokenRepository) {
        if (secretKey == null || secretKey.length() < 32) {
            logger.error("Invalid secret key. It must be at least 32 characters long.");
            throw new IllegalArgumentException("Secret key must be at least 32 characters long.");
        }
        this.SECRET_KEY = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.blacklistedTokenRepository = blacklistedTokenRepository;
        logger.info("JWT Service initialized successfully");
    }

    public void blacklistToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                logger.warn("Attempted to blacklist null or empty token");
                throw new IllegalArgumentException("Token cannot be null or empty");
            }

            Claims claims = extractClaims(token);
            Date expiryDate = claims.getExpiration();
            BlacklistedToken blacklistedToken = new BlacklistedToken(token, expiryDate);
            blacklistedTokenRepository.save(blacklistedToken);
            logger.info("Token blacklisted successfully");
        } catch (Exception e) {
            logger.error("Failed to blacklist token: {}", e.getMessage());
            throw new RuntimeException("Failed to blacklist token", e);
        }
    }

    public boolean isTokenBlacklisted(String token) {
        if (token == null || token.trim().isEmpty()) {
            logger.warn("Attempted to check null or empty token for blacklist");
            return true;
        }
        return blacklistedTokenRepository.existsByToken(token);
    }

    public String generateToken(String email, String username) {
        if (email == null || username == null) {
            logger.error("Email or username is null");
            throw new IllegalArgumentException("Email and username cannot be null");
        }

        logger.info("Generating token for email: {}", email);
        try {
            String token = Jwts.builder()
                    .setSubject(email)
                    .claim("email", email)
                    .claim("username", username)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                    .signWith(SECRET_KEY)
                    .compact();
            logger.info("JWT token generated successfully");
            return token;
        } catch (Exception e) {
            logger.error("Token generation failed: {}", e.getMessage());
            throw new RuntimeException("Failed to generate token", e);
        }
    }

    public Claims extractClaims(String token) {
        if (token == null || token.trim().isEmpty()) {
            logger.error("Attempted to extract claims from null or empty token");
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        try {
            return Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            logger.error("Failed to extract claims: {}", e.getMessage());
            throw new RuntimeException("Failed to extract claims from token", e);
        }
    }

    public String extractUsername(String token) {
        try {
            String username = extractClaims(token).get("username", String.class);
            if (username == null) {
                logger.warn("Username claim not found in token");
                throw new RuntimeException("Username not found in token");
            }
            return username;
        } catch (Exception e) {
            logger.error("Failed to extract username: {}", e.getMessage());
            throw new RuntimeException("Failed to extract username from token", e);
        }
    }

    public String extractEmail(String token) {
        try {
            String email = extractClaims(token).get("email", String.class);
            if (email == null) {
                logger.warn("Email claim not found in token");
                throw new RuntimeException("Email not found in token");
            }
            return email;
        } catch (Exception e) {
            logger.error("Failed to extract email: {}", e.getMessage());
            throw new RuntimeException("Failed to extract email from token", e);
        }
    }

    public Map<String, String> extractUserDetails(String token) {
        try {
            Claims claims = extractClaims(token);
            Map<String, String> userDetails = new HashMap<>();

            String username = claims.get("username", String.class);
            String email = claims.get("email", String.class);

            if (username == null || email == null) {
                logger.warn("Required claims missing from token");
                throw new RuntimeException("Required claims missing from token");
            }

            userDetails.put("username", username);
            userDetails.put("email", email);
            return userDetails;
        } catch (Exception e) {
            logger.error("Failed to extract user details: {}", e.getMessage());
            throw new RuntimeException("Failed to extract user details from token", e);
        }
    }

    public boolean validateToken(String token) {
        if (token == null || token.trim().isEmpty()) {
            logger.warn("Attempted to validate null or empty token");
            return false;
        }

        if (isTokenBlacklisted(token)) {
            logger.warn("Token is blacklisted");
            return false;
        }

        try {
            Claims claims = extractClaims(token);
            boolean isValid = !claims.getExpiration().before(new Date());

            if (!isValid) {
                logger.warn("Token has expired");
            }

            return isValid;
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
}