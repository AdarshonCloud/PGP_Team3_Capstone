
package com.ascendpgp.customerlogin.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class LoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization logic if needed
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Log request details
        logger.info("Incoming request: [{} {}] from {}", httpRequest.getMethod(), httpRequest.getRequestURI(),
                httpRequest.getRemoteAddr());

        chain.doFilter(request, response);

        // Log response details
        logger.info("Outgoing response: [{}] for [{} {}]", httpResponse.getStatus(), httpRequest.getMethod(),
                httpRequest.getRequestURI());
    }

    @Override
    public void destroy() {
        // Cleanup logic if needed
    }
}
