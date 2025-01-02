package com.ascendpgp.creditcard.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mongodb.MongoTimeoutException;


public class MongoExceptionUtils {

    private static final Logger logger = LoggerFactory.getLogger(MongoExceptionUtils.class);

    public static void handleMongoException(Exception ex) {
        if (ex instanceof com.mongodb.MongoTimeoutException || ex instanceof com.mongodb.MongoSocketException) {
            logger.error("MongoDB connectivity issue: {}", ex.getMessage(), ex);
            throw new MongoTimeoutException("Database connectivity issue occurred.");
        }
        logger.error("Unknown MongoDB error: {}", ex.getMessage(), ex);
        throw new RuntimeException("Unexpected MongoDB error occurred.");
    }
}