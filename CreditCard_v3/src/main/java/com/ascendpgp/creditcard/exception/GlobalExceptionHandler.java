
package com.ascendpgp.creditcard.exception;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import com.azure.core.exception.ResourceNotFoundException;
import com.mongodb.MongoTimeoutException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGenericException(Exception ex) {
        logger.error("An unexpected error occurred: {}", ex.getMessage(), ex);
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "An unexpected error occurred. Please try again later.");
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<String> handleNullPointerException(NullPointerException ex) {
        logger.error("Null pointer exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("A required value is missing. Please check your request.");
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<String> handleResourceNotFoundException(ResourceNotFoundException ex) {
        logger.error("Resource not found: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
    }

    @ExceptionHandler(CustomAddCardException.class)
    public ResponseEntity<String> handleCustomAddCardException(CustomAddCardException ex) {
        logger.warn("Custom add card exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(CardAlreadyDeletedException.class)
    public ResponseEntity<String> handleCardAlreadyDeletedException(CardAlreadyDeletedException ex) {
        logger.warn("Card already deleted exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(CardAlreadyExistsException.class)
    public ResponseEntity<String> handleCardAlreadyExistsException(CardAlreadyExistsException ex) {
        logger.warn("Card already exists exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
    }

    @ExceptionHandler(CardNotFoundException.class)
    public ResponseEntity<String> handleCardNotFoundException(CardNotFoundException ex) {
        logger.warn("Card not found: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
    }

    @ExceptionHandler(InvalidCardDetailsException.class)
    public ResponseEntity<String> handleInvalidCardDetailsException(InvalidCardDetailsException ex) {
        logger.warn("Invalid card details: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(InvalidOtpException.class)
    public ResponseEntity<String> handleInvalidOtpException(InvalidOtpException ex) {
        logger.error("Invalid OTP Exception: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }


    // Handle 404 Not Found
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<String> handleNoHandlerFoundException(NoHandlerFoundException ex) {
        logger.warn("No handler found for the requested endpoint: {}", ex.getRequestURL());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body("The endpoint you are trying to access does not exist. Please check the URL or contact support.");
    }

    //MongoDB Time Out
    @ExceptionHandler(MongoTimeoutException.class)
    public ResponseEntity<?> handleMongoTimeoutException(MongoTimeoutException ex) {
        logger.error("MongoDB exception occurred: {}", ex.getMessage(), ex);

        // Respond with a user-friendly message
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", "A database connectivity issue occurred. Please try again later.");
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // Invalid HTTP Method (405)
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<String> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        logger.warn("Invalid HTTP method: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body("This HTTP method is not allowed for the requested endpoint.");
    }

    //Invalid Media Type (415)
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<String> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex) {
        logger.warn("Unsupported media type: {}", ex.getContentType());
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body("The media type you provided is not supported. Please use a supported media type.");
    }


    // Illegal State Exception
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<String> handleIllegalStateException(IllegalStateException ex) {
        logger.error("Illegal state exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("The application encountered an unexpected state. Please try again later.");
    }
}