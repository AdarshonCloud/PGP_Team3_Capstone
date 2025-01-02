package com.ascendpgp.creditcard.exception;

public class CardUpdateException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;
	
    public CardUpdateException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public CardUpdateException(String message) {
        super(message);
    }
}
