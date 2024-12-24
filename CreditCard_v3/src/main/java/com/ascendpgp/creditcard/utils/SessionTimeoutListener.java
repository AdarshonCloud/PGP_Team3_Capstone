package com.ascendpgp.creditcard.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;

public class SessionTimeoutListener implements HttpSessionListener {
    private static final Logger logger = LoggerFactory.getLogger(SessionTimeoutListener.class);

    @Override
    public void sessionCreated(HttpSessionEvent se) {
        logger.info("Session created: ID [{}], Timeout [{}] seconds", 
                    se.getSession().getId(), se.getSession().getMaxInactiveInterval());
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        logger.warn("Session destroyed: ID [{}]", se.getSession().getId());
    }
}