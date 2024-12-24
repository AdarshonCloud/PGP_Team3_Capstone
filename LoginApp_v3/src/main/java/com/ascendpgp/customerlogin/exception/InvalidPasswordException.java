package com.ascendpgp.customerlogin.exception;

public class InvalidPasswordException extends CustomerServiceException {
	
	 private static final long serialVersionUID = 1L;

   public InvalidPasswordException(String message) {
       super(message);
   }
}
