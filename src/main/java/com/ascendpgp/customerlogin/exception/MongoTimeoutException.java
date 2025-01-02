package com.ascendpgp.customerlogin.exception;

public class MongoTimeoutException extends RuntimeException {
	
	 private static final long serialVersionUID = 1L;

  public MongoTimeoutException(String message) {
      super(message);
  }
}

