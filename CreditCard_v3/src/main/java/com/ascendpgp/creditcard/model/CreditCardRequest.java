package com.ascendpgp.creditcard.model;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class CreditCardRequest {

    @NotNull(message = "Card number is required")
    @Pattern(regexp = "\\d{16}", message = "Card number must be 16 digits")
    private String cardNumber;

    @NotNull(message = "CVV is required")
    private Integer cvv; // Changed to Integer to match database

    @NotNull(message = "Expiry month is required")
    private Integer expiryMonth; // Changed to Integer to match database

    @NotNull(message = "Expiry year is required")
    private Integer expiryYear; // Changed to Integer to match database

    @NotNull(message = "Wire transaction vendor is required")
    @Size(max = 50, message = "Vendor name must not exceed 50 characters")
    private String wireTransactionVendor;

    // Getters and Setters
    public String getCardNumber() {
        return cardNumber;
    }

    public void setCardNumber(String cardNumber) {
        this.cardNumber = cardNumber;
    }

    public Integer getCvv() {
        return cvv;
    }

    public void setCvv(Integer cvv) {
        this.cvv = cvv;
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

    public String getWireTransactionVendor() {
        return wireTransactionVendor;
    }

    public void setWireTransactionVendor(String wireTransactionVendor) {
        this.wireTransactionVendor = wireTransactionVendor;
    }
}