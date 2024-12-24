package com.ascendpgp.creditcard.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.ascendpgp.creditcard.exception.CardAlreadyDeletedException;
import com.ascendpgp.creditcard.exception.CardAlreadyExistsException;
import com.ascendpgp.creditcard.exception.CardNotFoundException;
import com.ascendpgp.creditcard.exception.CustomAddCardException;
import com.ascendpgp.creditcard.model.CreditCard;
import com.ascendpgp.creditcard.model.CreditCard.CardDetails;
import com.ascendpgp.creditcard.model.CreditCardRequest;
import com.ascendpgp.creditcard.repository.CreditCardRepository;
import com.ascendpgp.creditcard.repository.CustomCreditCardRepository;
import com.ascendpgp.creditcard.utils.EncryptionUtil;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;

@Service
public class CreditCardService {

    private static final Logger logger = LoggerFactory.getLogger(CreditCardService.class);

    @Autowired
    private CreditCardRepository creditCardRepository;

    @Autowired
    @Qualifier("customCreditCardRepositoryImpl")
    private CustomCreditCardRepository customCreditCardRepository;

    @Autowired
    private EncryptionUtil encryptionUtil;

    @Autowired
    private FallbackService fallbackService;

    private static final String CIRCUIT_BREAKER_NAME = "creditCardServiceCircuitBreaker";
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long RETRY_DELAY_MS = 500; // 500ms delay between retries

    /**
     * Add a new credit card for a user.
     *
     * @param username Username of the user.
     * @param request  CreditCardRequest containing the card details.
     * @return CardDetails of the added card.
     */
    @CircuitBreaker(name = CIRCUIT_BREAKER_NAME, fallbackMethod = "fallbackService.addCreditCardFallback")
    public CardDetails addCreditCard(String username, CreditCardRequest request) {
        logger.info("Adding a new credit card for user: {}", username);

     // Step 1: Check if the card already exists
        Optional<CreditCard.CardDetails> existingCard = customCreditCardRepository.findCardDetailsByNumber(username, request.getCardNumber());
        if (existingCard.isPresent()) {
            CreditCard.CardDetails existingDetails = existingCard.get();
            if (Boolean.FALSE.equals(existingDetails.isDeleted())) {
                // If the card exists and is active, throw an exception
                throw new CardAlreadyExistsException("Credit card already exists for user: " + username);
            } else {
                // Reactivate the soft-deleted card
                logger.info("Soft-deleted card found. Reactivating for user: {}, cardId: {}", username, existingDetails.getCreditCardId());
                existingDetails.setDeleted(false);  // Set deleted to false
                existingDetails.setStatus("enabled");  // Set status to enabled
                
                // Use the updated method to apply the changes
                customCreditCardRepository.updateCreditCard(username, existingDetails.getCreditCardId(), existingDetails);
                
                logger.info("Soft-deleted card reactivated successfully for user: {}", username);
                return existingDetails;
            }
        }

        // Step 2: Validate expiry date
        validateExpiryDate(request.getExpiryMonth(), request.getExpiryYear());

        // Step 3: Encrypt and mask sensitive details
        String encryptedCardNumber;
        String maskedCardNumber;
        Integer hashedEncryptedCvv;
        try {
            encryptedCardNumber = encryptionUtil.encrypt(request.getCardNumber());
            maskedCardNumber = maskCardNumber(request.getCardNumber());
            String encryptedCvv = encryptionUtil.encryptInteger(request.getCvv());
            hashedEncryptedCvv = encryptedCvv.hashCode();
        } catch (Exception e) {
            logger.error("Error encrypting sensitive information for user: {}", username, e);
            throw new RuntimeException("Failed to encrypt sensitive data.");
        }

        // Step 4: Populate CardDetails object
        CardDetails cardDetails = new CardDetails();
        cardDetails.setCreditCardId(generateUniqueId());
        cardDetails.setCreditCardNumber(encryptedCardNumber);
        cardDetails.setExpiryMonth(request.getExpiryMonth());
        cardDetails.setExpiryYear(request.getExpiryYear());
        cardDetails.setCvv(hashedEncryptedCvv);
        cardDetails.setWireTransactionVendor(request.getWireTransactionVendor());
        cardDetails.setStatus("enabled");
        cardDetails.setDeleted(false);

        // Step 5: Add card to the database
        try {
            customCreditCardRepository.addCreditCard(username, cardDetails);
            logger.info("Successfully added credit card for user: {} (Masked: {})", username, maskedCardNumber);
        } catch (Exception e) {
            logger.error("Error adding credit card for user: {}", username, e);
            throw new RuntimeException("Failed to add credit card.");
        }

        logger.info("Verified successfully: Card was added for user: {} (Masked: {})", username, maskCardNumber(request.getCardNumber()));
        return cardDetails;
    }
    
    
    /**
     * Soft delete a credit card for a user.
     *
     * @param username Username of the user.
     * @param cardNumber Card number of the credit card to be deleted.
     */
    @CircuitBreaker(name = CIRCUIT_BREAKER_NAME, fallbackMethod = "fallbackService.softDeleteCreditCardFallback")
    public String softDeleteCreditCard(String username, String cardNumber) {
        logger.info("Soft deleting credit card for user: {}, card number: {}", username, cardNumber);

        try {
            // Find the credit card using the existing method
            Optional<CreditCard.CardDetails> cardDetailsOpt = customCreditCardRepository.findCardDetailsByNumber(username, cardNumber);

            if (cardDetailsOpt.isEmpty()) {
                logger.error("No matching card found for card number: {} and user: {}", cardNumber, username);
                throw new CardNotFoundException(String.format("Credit card not found for user %s.", cardNumber, username));
            }

            CreditCard.CardDetails cardDetails = cardDetailsOpt.get();

            // Check if the card is already deleted
            if (cardDetails.isDeleted()) {
                logger.warn("Card number: {} is already marked as deleted for user: {}", cardNumber, username);
                throw new CardAlreadyDeletedException("Credit card not found.");
            }

            // Set the attributes for soft delete
            cardDetails.setDeleted(true);
            cardDetails.setStatus("disabled");

            // Call the updated updateCreditCard method
            customCreditCardRepository.updateCreditCard(username, cardDetails.getCreditCardId(), cardDetails);

            // Mask the card number before returning
            String maskedCardNumber = maskCardNumber(cardDetails.getCreditCardNumber());

            logger.info("Successfully soft-deleted credit card with number: {}", maskedCardNumber);

            return String.format("Credit card number %s successfully deleted.", maskedCardNumber);
        }  catch (CardNotFoundException | CardAlreadyDeletedException e) {
            // Log and rethrow specific exceptions
            logger.error(e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            // Log and rethrow generic exceptions as RuntimeException
            logger.error("Unexpected error soft-deleting credit card for user: {}, card number: {}", username, cardNumber, e);
            throw new RuntimeException("Failed to delete the credit card.", e);
        }
    }
    
    /**
     * Fetch active (non-deleted and enabled) credit cards for a user.
     *
     * @param username Username of the user.
     * @return List of active CardDetails.
     */
    @CircuitBreaker(name = CIRCUIT_BREAKER_NAME, fallbackMethod = "fallbackService.getActiveCreditCardsFallback")
    public List<CardDetails> getActiveCreditCards(String username) {
        logger.info("Fetching active credit cards for user: {}", username);

        List<CardDetails> activeCards = customCreditCardRepository.findActiveCreditCards(username);

        if (activeCards.isEmpty()) {
            logger.info("No active credit cards found for user: {}", username);
        } else {
            logger.info("Retrieved {} active credit cards for user: {}", activeCards.size(), username);
        }

        // Decrypt and mask sensitive details before returning
        activeCards.forEach(this::decryptAndMaskCardDetails);

        return activeCards;
    }

    /**
     * Toggle the state of a credit card (enable/disable).
     *
     * @param username Username of the user.
     * @param cardNumber Card number of the credit card to toggle.
     */
    @CircuitBreaker(name = CIRCUIT_BREAKER_NAME, fallbackMethod = "fallbackService.toggleCreditCardFallback")
    public CreditCard.CardDetails toggleCreditCardStatus(String username, String creditCardNumber) {
        logger.info("Toggling status for username: {}, creditCardNumber: {}", username, creditCardNumber);

        // Find the credit card details
        Optional<CreditCard.CardDetails> cardDetailsOpt = customCreditCardRepository.findCardDetailsByNumber(username, creditCardNumber);
        if (cardDetailsOpt.isEmpty()) {
            logger.error("No matching credit card found for username: {}, creditCardNumber: {}", username, creditCardNumber);
            throw new CardNotFoundException("Card doesn't exist.");
        }

        CreditCard.CardDetails cardDetails = cardDetailsOpt.get();
        logger.info("Fetched card details: {}", cardDetails);

        // Ensure the card is not soft-deleted
        if (cardDetails.isDeleted()) {
            logger.error("Attempt to toggle a soft-deleted card for username: {}, creditCardNumber: {}", username, creditCardNumber);
            throw new RuntimeException("Card is soft-deleted and cannot be toggled.");
        }

        // Determine the new status
        String currentStatus = cardDetails.getStatus();
        String newStatus = "enabled".equals(currentStatus) ? "disabled" : "enabled";
        logger.info("Current status: {}, New status: {}", currentStatus, newStatus);

        // Only perform the update if the status is different
        if (currentStatus.equals(newStatus)) {
            logger.info("Card status is already {} for card number: {}", newStatus, creditCardNumber);
            return cardDetails;  // No need to update if status is already the desired state
        }

        // Update the credit card status in the database
        customCreditCardRepository.updateCreditCardStatus(
            username,
            cardDetails.getCreditCardId(),
            cardDetails.getCreditCardNumber(),
            cardDetails.isDeleted(),
            newStatus
        );

        // Update the cardDetails object to reflect the new status
        cardDetails.setStatus(newStatus);

        // Return the updated card details
        return cardDetails;
    }
    

    private void decryptAndMaskCardDetails(CardDetails cardDetails) {
        try {
            String cardNumber = cardDetails.getCreditCardNumber();
            if (encryptionUtil.isEncrypted(cardNumber)) {
                logger.info("Decrypting encrypted credit card number for card ID: {}", cardDetails.getCreditCardId());
                cardDetails.setCreditCardNumber(maskCardNumber(encryptionUtil.decrypt(cardNumber)));
            } else {
                logger.info("Card number is not encrypted for card ID: {}. Returning as-is.", cardDetails.getCreditCardId());
                cardDetails.setCreditCardNumber(maskCardNumber(cardNumber));
            }
            cardDetails.setCvv(null); // CVV is hashed
        } catch (Exception e) {
            logger.error("Error decrypting card details for card ID: {}", cardDetails.getCreditCardId(), e);
        }
    }
    
    
    //Generate unique random ID
    private Integer generateUniqueId() {
        return (int) (Math.random() * Integer.MAX_VALUE);
    }
    
    // Masking Credit Card method
    private String maskCardNumber(String cardNumber) {
        // Handle null or empty input
        if (cardNumber == null || cardNumber.isEmpty()) {
            logger.warn("Card number is null or empty, returning default masked value.");
            return "XXXXXXXXXXXX****";
        }

        // Check for standard card length (16 or more digits)
        if (cardNumber.length() >= 16) {
            // Mask all but the last 4 digits
            return "XXXXXXXXXXXX" + cardNumber.substring(cardNumber.length() - 4);
        }

        // Handle unexpected card number formats
        logger.warn("Unexpected card number length: {}. Returning default masked value.", cardNumber.length());
        return "XXXXXXXXXXXX****"; // Default for invalid or short card numbers
    }

    /**
     * Matches a stored card number with the input card number.
     *
     * @param storedCard The card number stored in the database (encrypted or plain).
     * @param inputCard  The card number provided in the request.
     * @return True if the card numbers match.
     */
    public boolean matchCardNumber(String storedNumber, String inputNumber) {
        logger.debug("Matching stored number: {} with input number: {}", storedNumber, inputNumber);

        // Check if input is masked
        if (isMaskedNumber(inputNumber)) {
            logger.debug("Input number appears to be masked: {}", inputNumber);
            if (matchLastFourDigits(storedNumber, inputNumber.substring(inputNumber.length() - 4))) {
                return true;
            }
        } else {
            // Exact match for non-masked numbers
            if (storedNumber.equals(inputNumber)) {
                logger.debug("Exact match found.");
                return true;
            }
        }

        logger.debug("No match found.");
        return false;
    }
    
    private boolean matchLastFourDigits(String maskedCard, String inputCard) {
        // Extract the last 4 digits from both the masked card and input card
        String lastFourMasked = maskedCard.substring(maskedCard.length() - 4);
        String lastFourInput = inputCard.substring(inputCard.length() - 4);
        return lastFourMasked.equals(lastFourInput);
    }
    
    private boolean isMaskedNumber(String cardNumber) {
        // Regex checks if card starts with XXXX, ****, ####, or any combination
        boolean isMasked = cardNumber.startsWith("XXXX") || cardNumber.startsWith("****");
        logger.debug("Card number {} is masked: {}", cardNumber, isMasked);
        return isMasked;
    }

    private void validateExpiryDate(Integer expiryMonth, Integer expiryYear) {
        if (expiryMonth < 1 || expiryMonth > 12) {
            throw new RuntimeException("Invalid expiry month. Must be between 1 and 12.");
        }

        LocalDateTime now = LocalDateTime.now();
        int currentYear = now.getYear();
        int currentMonth = now.getMonthValue();

        // Handle 2-digit years by converting them to 4-digit years
        if (expiryYear < 100) {
            expiryYear += (currentYear / 100) * 100;
            // If the calculated year is in the past, roll over to the next century
            if (expiryYear < currentYear) {
                expiryYear += 100;
            }
        }

        // Check if the expiry year is in the past
        if (expiryYear < currentYear) {
            throw new RuntimeException("Invalid expiry year. Cannot be in the past.");
        }

        // If the expiry year is the current year, validate the expiry month
        if (expiryYear == currentYear && expiryMonth < currentMonth) {
            throw new RuntimeException("Invalid expiry month. Cannot be in the past.");
        }
    }
}