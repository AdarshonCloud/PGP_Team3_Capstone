package com.ascendpgp.customerlogin.exception;

public class AccountNotValidatedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AccountNotValidatedException(String message) {
        super(message);
    }
}