package com.ascendpgp.creditcard.service;

import com.ascendpgp.creditcard.model.CreditCardRequest;
import com.ascendpgp.creditcard.exception.CardAlreadyDeletedException;
import com.ascendpgp.creditcard.model.CreditCard.CardDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class FallbackService {

    private static final Logger logger = LoggerFactory.getLogger(FallbackService.class);

    /**
     * Fallback method for adding a credit card.
     *
     * @param username Username of the user.
     * @param request  CreditCardRequest containing credit card details.
     * @param throwable Exception that caused the fallback.
     * @return Default CardDetails object.
     */
    public CardDetails addCreditCardFallback(String username, CreditCardRequest request, Throwable throwable) {
        logger.error("Fallback triggered for addCreditCard. Username: {}, Reason: {}", username, throwable.getMessage());
        CardDetails fallbackCardDetails = new CardDetails();
        fallbackCardDetails.setStatus("fallback");
        return fallbackCardDetails;
    }

    /**
     * Fallback method for soft deleting a credit card.
     *
     * @param username   Username of the user.
     * @param cardNumber Card number of the credit card.
     * @param throwable  Exception that caused the fallback.
     */
    public void softDeleteCreditCardFallback(String username, String cardNumber, Throwable throwable) {
        logger.error("Fallback triggered for softDeleteCreditCard. Username: {}, CardNumber: {}, Reason: {}",
                username, cardNumber, throwable.getMessage());
        
        if (throwable instanceof CardAlreadyDeletedException) {
            logger.warn("Card is already deleted: {}", cardNumber);
        } else {
            logger.error("An unexpected error occurred while soft deleting card: {}", throwable.getMessage());
        }

    }

    /**
     * Fallback method for retrieving active credit cards.
     *
     * @param username  Username of the user.
     * @param throwable Exception that caused the fallback.
     * @return Empty list of CardDetails.
     */
    public List<CardDetails> getActiveCreditCardsFallback(String username, Throwable throwable) {
        logger.error("Fallback triggered for getActiveCreditCards. Username: {}, Reason: {}", username, throwable.getMessage());
        return Collections.emptyList();
    }

    /**
     * Fallback method for toggling the state of a credit card.
     *
     * @param username   Username of the user.
     * @param cardNumber Card number of the credit card.
     * @param throwable  Exception that caused the fallback.
     */
    public void toggleCreditCardFallback(String username, String creditCardNumber, Throwable throwable) {
        logger.error("Fallback triggered for toggleCreditCardStatus. Username: {}, CreditCardNumber: {}, Error: {}",
                username, creditCardNumber, throwable.getMessage());

        // If the exception is related to a soft-deleted card, handle it separately
        if (throwable.getMessage().contains("soft-deleted")) {
            throw new RuntimeException("Card is marked deleted and cannot be toggled.");
        }

        // For other exceptions, return a generic service unavailable message
        throw new RuntimeException("Service unavailable. Please try again later.");
    }
}