package com.ascendpgp.creditcard.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private final RestTemplate restTemplate;
    private final String loginServiceUrl;
    private final String jwtSecret;
    private final String encryptionSecretKey;

    public JwtService(RestTemplate restTemplate,
                      @Value("${login.service.url}") String loginServiceUrl,
                      @Value("${jwt.secret}") String jwtSecret,
                      @Value("${encryption.secret.key}") String encryptionSecretKey) {
        this.restTemplate = restTemplate;
        this.loginServiceUrl = loginServiceUrl;
        this.jwtSecret = jwtSecret;
        this.encryptionSecretKey = encryptionSecretKey;
    }
    
    private final Cache<String, Boolean> tokenBlacklistCache = Caffeine.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES) // Cache tokens for 10 minutes
            .maximumSize(1000) // Limit the cache size
            .build();

    /**
     * Check if a token is blacklisted.
     */
    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklistCache.get(token, this::fetchTokenBlacklistStatus);
    }

    /**
     * Fetch the blacklist status of a token from the external service.
     */
    private boolean fetchTokenBlacklistStatus(String token) {
        try {
            String validationApiUrl = "http://localhost:8081/api/customer/token/validate?token=" + token;
            ResponseEntity<String> response = restTemplate.getForEntity(validationApiUrl, String.class);

            // Token is considered blacklisted if the response status is not 200 OK
            return !response.getStatusCode().is2xxSuccessful();
        } catch (Exception ex) {
            logger.error("Error fetching token blacklist status: {}", ex.getMessage());
            return true; // Assume blacklisted if validation fails
        }
    }

    /**
     * Validate the token locally or via remote validation.
     *
     * @param token JWT token to validate.
     * @return true if the token is valid, false otherwise.
     */
    public boolean validateToken(String token) {
        try {
            // Local validation using the secret key
            Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
                .build()
                .parseClaimsJws(token);

            logger.info("JWT token is valid (local validation): {}", maskToken(token));
            return true;
        } catch (Exception localValidationException) {
            logger.warn("Local JWT validation failed. Falling back to remote validation: {}", maskToken(token), localValidationException);

            // Fallback to remote validation
            return validateTokenRemotely(token);
        }
    }

    /**
     * Validate the token remotely by calling the login service.
     *
     * @param token JWT token to validate.
     * @return true if the token is valid, false otherwise.
     */
    private boolean validateTokenRemotely(String token) {
        try {
            validateAndExtractTokenDetails(token);
            return true;
        } catch (Exception e) {
            logger.error("Remote token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extract username from the token.
     *
     * @param token JWT token.
     * @return Extracted username.
     */
    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("username", String.class);
    }

    /**
     * Validate the token and extract user details from the login service.
     *
     * @param token JWT token to validate.
     * @return Map containing extracted user details like username and email.
     */
    public Map<String, String> validateAndExtractTokenDetails(String token) {
        logger.info("Validating token: {}", maskToken(token));

        String url = loginServiceUrl + "/api/customer/jwt/validate?token=" + token;
        logger.info("Calling remote validation endpoint: {}", url);

        ResponseEntity<Map<String, String>> response = restTemplate.exchange(
            url,
            HttpMethod.GET,
            null,
            new ParameterizedTypeReference<>() {}
        );

        if (response.getStatusCode().is2xxSuccessful()) {
            Map<String, String> tokenDetails = response.getBody();
            logger.info("Remote validation succeeded. Extracted details: {}", tokenDetails);
            return tokenDetails;
        } else {
            String errorMessage = getErrorMessage(response);
            logger.error("Remote validation failed: {}", errorMessage);
            throw new RuntimeException("Token validation failed: " + errorMessage);
        }
    }

    /**
     * Extract all claims from the JWT token.
     *
     * @param token JWT token.
     * @return Extracted claims.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    /**
     * Encrypt sensitive data using the encryption secret key.
     *
     * @param data Data to encrypt.
     * @return Encrypted data as a Base64 encoded string.
     */
    public String encrypt(String data) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(encryptionSecretKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            logger.error("Encryption failed: {}", e.getMessage());
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypt sensitive data using the encryption secret key.
     *
     * @param encryptedData Encrypted data as a Base64 encoded string.
     * @return Decrypted data.
     */
    public String decrypt(String encryptedData) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(encryptionSecretKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedData = Base64.getDecoder().decode(encryptedData);
            return new String(cipher.doFinal(decodedData));
        } catch (Exception e) {
            logger.error("Decryption failed: {}", e.getMessage());
            throw new RuntimeException("Decryption failed", e);
        }
    }

    /**
     * Mask a token to hide sensitive information in logs.
     *
     * @param token The original token.
     * @return Masked token.
     */
    private String maskToken(String token) {
        return token != null && token.length() > 10 ? token.substring(0, 6) + "******" : "******";
    }

    /**
     * Extract error message from response or provide a fallback.
     *
     * @param response ResponseEntity containing the error details.
     * @return Extracted error message.
     */
    private String getErrorMessage(ResponseEntity<Map<String, String>> response) {
        return response.getBody() != null 
                ? response.getBody().getOrDefault("error", "Unknown error")
                : "No error details provided";
    }
}