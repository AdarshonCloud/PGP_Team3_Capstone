package com.ascendpgp.customerlogin.exception;

public class CustomerServiceException extends RuntimeException {
	
	 private static final long serialVersionUID = 1L;

   public CustomerServiceException(String message) {
       super(message);
   }
}
