package com.ascendpgp.customerlogin.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Document(collection = "CreditCard")
public class CreditCard {
    @Id
    private String id;
    private String username;
    private String nameOnTheCard;
    private List<CreditCardDetail> creditcards;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getNameOnTheCard() {
        return nameOnTheCard;
    }

    public void setNameOnTheCard(String nameOnTheCard) {
        this.nameOnTheCard = nameOnTheCard;
    }

    public List<CreditCardDetail> getCreditcards() {
        return creditcards;
    }

    public void setCreditcards(List<CreditCardDetail> creditcards) {
        this.creditcards = creditcards;
    }

    public static class CreditCardDetail {
        private int creditCardId;
        private String creditCardNumber;
        private int expiryMonth;
        private int expiryYear;
        private int cvv;
        private String wireTransactionVendor;
        private String status;
        private boolean deleted; // delete declaration

        public int getCreditCardId() {
            return creditCardId;
        }

        public void setCreditCardId(int creditCardId) {
            this.creditCardId = creditCardId;
        }

        public String getCreditCardNumber() {
            return creditCardNumber;
        }

        public void setCreditCardNumber(String creditCardNumber) {
            this.creditCardNumber = creditCardNumber;
        }

        public int getExpiryMonth() {
            return expiryMonth;
        }

        public void setExpiryMonth(int expiryMonth) {
            this.expiryMonth = expiryMonth;
        }

        public int getExpiryYear() {
            return expiryYear;
        }

        public void setExpiryYear(int expiryYear) {
            this.expiryYear = expiryYear;
        }

        public int getCvv() {
            return cvv;
        }

        public void setCvv(int cvv) {
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
        
      //delete operation    
        public boolean isDeleted() {
        	return deleted;
        }
        
        public void setDeleted(boolean deleted) {
        	this.deleted =  deleted;
        }
    }
}
