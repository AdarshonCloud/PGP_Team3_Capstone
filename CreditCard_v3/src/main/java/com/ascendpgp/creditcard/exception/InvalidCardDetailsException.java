package com.ascendpgp.creditcard.exception;

public class InvalidCardDetailsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidCardDetailsException(String message) {
        super(message);
    }

    public InvalidCardDetailsException(String message, Throwable cause) {
        super(message, cause);
    }
}