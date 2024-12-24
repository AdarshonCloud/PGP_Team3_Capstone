package com.ascendpgp.creditcard.exception;

public class CustomAddCardException extends RuntimeException {
	
    // Explicitly declare serialVersionUID to suppress warnings
    private static final long serialVersionUID = 1L;
    
    public CustomAddCardException(String message) {
        super(message);
    }

    public CustomAddCardException(String message, Throwable cause) {
        super(message, cause);
    }
}
