package com.ascendpgp.creditcard.exception;

public class InvalidOtpException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidOtpException(String message) {
        super(message);
    }

    public InvalidOtpException(String message, Throwable cause) {
        super(message, cause);
    }
}