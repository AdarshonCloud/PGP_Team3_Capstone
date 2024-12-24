package com.ascendpgp.creditcard.exception;

/**
 * Exception thrown when attempting to add a card that already exists.
 */
public class CardAlreadyExistsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CardAlreadyExistsException(String message) {
        super(message);
    }
}