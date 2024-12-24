package com.ascendpgp.creditcard;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

import ch.qos.logback.classic.LoggerContext;

@SpringBootApplication
@EnableMongoRepositories(basePackages = "com.ascendpgp.creditcard.repository")
class CreditCardApplication {
	public static void main(String[] args) {

	    Logger logger = LoggerFactory.getLogger(CreditCardApplication.class);
	    logger.info("Testing if the logger is initialized.");

	    LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
	    context.putProperty("appName", "CreditCardApp"); // Hardcode temporarily
	    SpringApplication.run(CreditCardApplication.class, args);
	    logger.info("Application has started successfully!");
	}
}
