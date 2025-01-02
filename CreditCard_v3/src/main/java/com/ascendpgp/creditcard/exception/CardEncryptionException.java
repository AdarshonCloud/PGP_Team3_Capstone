package com.ascendpgp.creditcard.exception;

public class CardEncryptionException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;
	
    public CardEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
