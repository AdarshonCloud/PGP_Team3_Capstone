package com.ascendpgp.creditcard.repository;

import com.ascendpgp.creditcard.model.CreditCard;
import com.ascendpgp.creditcard.model.CreditCard.CardDetails;

import java.util.List;
import java.util.Optional;

public interface CustomCreditCardRepository {
    void addCreditCard(String username, CardDetails cardDetails);
    void updateCreditCard(String username, Integer creditCardId, CreditCard.CardDetails cardDetails);
    void softDeleteCreditCard(String username, int creditCardId, String creditCardNumber);
    void updateCreditCardStatus(String username, int creditCardId, String creditCardNumber, boolean deleted, String newStatus);
    Optional<CreditCard.CardDetails> findCardDetailsByNumber(String username, String cardNumber);
    List<CardDetails> findActiveCreditCards(String username);
    Optional<CardDetails> findUnmaskedCardDetailsByNumber(String username, String cardNumber);
}