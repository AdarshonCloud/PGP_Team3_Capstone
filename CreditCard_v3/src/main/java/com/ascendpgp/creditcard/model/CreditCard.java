package com.ascendpgp.creditcard.model;

import java.util.List;

public class CreditCard {

    private String username;
    private List<CardDetails> creditcards; 

    // Getters and Setters
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<CardDetails> getCreditcards() {
        return creditcards;
    }

    public void setCreditcards(List<CardDetails> creditcards) {
        this.creditcards = creditcards;
    }

    // Inner Class for Card Details
    public static class CardDetails {
        private Integer creditCardId; // Matches Integer from DB
        private String creditCardNumber; // Encrypted for security
        private Integer expiryMonth; // Matches Integer from DB
        private Integer expiryYear; // Matches Integer from DB
        private Integer cvv; // Matches Integer from DB
        private String wireTransactionVendor; // Matches String from DB
        private String status; // Matches String from DB
        private Boolean deleted; // Matches boolean from DB

        // Getters and Setters
        public Integer getCreditCardId() {
            return creditCardId;
        }

        public void setCreditCardId(Integer creditCardId) {
            this.creditCardId = creditCardId;
        }

        public String getCreditCardNumber() {
            return creditCardNumber;
        }

        public void setCreditCardNumber(String creditCardNumber) {
            this.creditCardNumber = creditCardNumber;
        }

        public Integer getExpiryMonth() {
            return expiryMonth;
        }

        public void setExpiryMonth(Integer expiryMonth) {
            this.expiryMonth = expiryMonth;
        }

        public Integer getExpiryYear() {
            return expiryYear;
        }

        public void setExpiryYear(Integer expiryYear) {
            this.expiryYear = expiryYear;
        }

        public Integer getCvv() {
            return cvv;
        }

        public void setCvv(Integer cvv) {
            this.cvv = cvv;
        }

        public String getWireTransactionVendor() {
            return wireTransactionVendor;
        }

        public void setWireTransactionVendor(String wireTransactionVendor) {
            this.wireTransactionVendor = wireTransactionVendor;
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public Boolean isDeleted() {
            return deleted;
        }

        public void setDeleted(Boolean deleted) {
            this.deleted = deleted;
        }
    }
}