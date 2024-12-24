package com.ascendpgp.customerlogin.exception;

public class WeakPasswordException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public WeakPasswordException(String message) {
        super(message);
    }
}
