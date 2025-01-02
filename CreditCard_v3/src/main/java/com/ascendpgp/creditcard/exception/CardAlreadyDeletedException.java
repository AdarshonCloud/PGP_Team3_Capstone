package com.ascendpgp.creditcard.exception;

public class CardAlreadyDeletedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public CardAlreadyDeletedException(String message) {
        super(message);
    }
    
    public CardAlreadyDeletedException(String message, Throwable cause) {
        super(message, cause);
    }
}