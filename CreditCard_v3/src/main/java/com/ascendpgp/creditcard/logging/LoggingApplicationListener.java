package com.ascendpgp.creditcard.logging;

import ch.qos.logback.classic.LoggerContext;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
public class LoggingApplicationListener implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        // Fetch the application name from Spring's environment
        String appName = event.getEnvironment().getProperty("spring.application.name", "UnknownApp");

        // Set the application name in Logback's context
        LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
        context.putProperty("appName", appName);
    }
}