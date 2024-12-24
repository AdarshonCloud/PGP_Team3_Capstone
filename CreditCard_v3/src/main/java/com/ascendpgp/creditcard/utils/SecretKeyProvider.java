package com.ascendpgp.creditcard.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SecretKeyProvider {

    private static final Logger logger = LoggerFactory.getLogger(SecretKeyProvider.class);

    @Value("${encryption.secret.key:}")
    private String keyFromProperties;

    @Value("${encryption.secret.source:properties}") // 'properties', 'environment', 'vault'
    private String keySource;

    public String getSecretKey() {
        switch (keySource.toLowerCase()) {
            case "environment":
                logger.info("Fetching secret key from environment variables.");
                return System.getenv("ENCRYPTION_SECRET_KEY");
            case "vault":
                logger.info("Fetching secret key from external vault.");
                return fetchKeyFromVault();
            case "properties":
            default:
                logger.info("Fetching secret key from application properties.");
                return keyFromProperties;
        }
    }

    private String fetchKeyFromVault() {
        // Placeholder for actual secret vault integration logic.
        // For example, fetching from AWS Secrets Manager or Azure Key Vault
        logger.info("Connecting to secret vault...");
        return "your-secret-key-from-vault"; // Replace with actual logic
    }
}