package com.ascendpgp.customerlogin.exception;

public class InvalidCredentialsException extends CustomerServiceException {
	
	 private static final long serialVersionUID = 1L;

   public InvalidCredentialsException(String message) {
       super(message);
   }
}
