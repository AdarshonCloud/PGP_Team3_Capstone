package com.ascendpgp.creditcard.logging;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class RequestLoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    public void init(FilterConfig filterConfig) { }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        logger.info("Incoming request: [{}] {}", httpRequest.getMethod(), httpRequest.getRequestURI());
        httpRequest.getHeaderNames().asIterator().forEachRemaining(
            header -> logger.info("Header [{}]: {}", header, httpRequest.getHeader(header))
        );

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() { }
}