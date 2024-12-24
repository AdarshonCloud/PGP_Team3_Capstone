package com.ascendpgp.creditcard.exception;

public class CardNotFoundException extends RuntimeException {
	
    // Explicitly declare serialVersionUID to suppress warnings
    private static final long serialVersionUID = 1L;
    
    public CardNotFoundException(String message) {
        super(message);
    }
}
