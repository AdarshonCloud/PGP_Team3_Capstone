package com.ascendpgp.customerlogin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;


import ch.qos.logback.classic.LoggerContext;

@SpringBootApplication
@EnableDiscoveryClient
public class CustomerloginApplication {
    public static void main(String[] args) {

	    Logger logger = LoggerFactory.getLogger(CustomerloginApplication.class);
	    logger.info("Testing if the logger is initialized.");
	    
	    LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
	    context.putProperty("appName", "CustomerLogin"); // Hardcode temporarily
        SpringApplication.run(CustomerloginApplication.class, args);
        logger.info("Application has started successfully!");
    }
}
