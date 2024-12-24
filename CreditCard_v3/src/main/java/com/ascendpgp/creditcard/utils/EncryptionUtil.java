package com.ascendpgp.creditcard.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class EncryptionUtil {

    private final String secretKey;

    @Autowired
    public EncryptionUtil(@Value("${encryption.secret.key}") String secretKey) {
        this.secretKey = secretKey;
    }

    
    // Encrypts a string
    public String encrypt(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Decrypts a string
    public String decrypt(String encryptedData) throws Exception {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedData));
    }

    // Encrypts an integer (e.g., cvv) as a string
    public String encryptInteger(Integer input) throws Exception {
        return encrypt(String.valueOf(input));
    }

    // Decrypts an integer stored as a string
    public Integer decryptInteger(String encrypted) throws Exception {
        return Integer.valueOf(decrypt(encrypted));
    }

    /**
     * Determines if a given string is encrypted.
     * Checks if the string can be successfully decrypted using the secret key.
     *
     * @param data The string to check.
     * @return true if the string is encrypted, false otherwise.
     */
    public boolean isEncrypted(String data) {
        try {
            decrypt(data); // Attempt to decrypt the data
            return true;   // If decryption succeeds, it's encrypted
        } catch (Exception e) {
            return false;  // If an exception occurs, it's not encrypted
        }
    }
    
}