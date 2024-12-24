package com.ascendpgp.creditcard.filters;

import com.ascendpgp.creditcard.utils.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtService jwtService;
    private final CsrfTokenRepository csrfTokenRepository;
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(JwtService jwtService, CsrfTokenRepository csrfTokenRepository) {
        this.jwtService = jwtService;
        this.csrfTokenRepository = csrfTokenRepository;
    }

    private boolean shouldSkipValidation(String requestUri) {
        return antPathMatcher.match("/api/customer/csrf-token", requestUri)
            || antPathMatcher.match("/v3/api-docs/**", requestUri)
            || antPathMatcher.match("/swagger-ui/**", requestUri)
            || antPathMatcher.match("/swagger-ui.html", requestUri)
            || antPathMatcher.match("/error", requestUri);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response, 
                                   FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        String httpMethod = request.getMethod();
        logger.info("Processing request URI: [{}], Method: [{}], Session ID: [{}]",
                requestUri, httpMethod, 
                (request.getSession(false) != null ? request.getSession(false).getId() : "No session"));

        logHeaders(request);

        if (shouldSkipValidation(requestUri)) {
            logger.info("Skipping JWT/CSRF validation for URI: {}", requestUri);
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.error("Missing or invalid Authorization header.");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, 
                                "Unauthorized: Missing or invalid Authorization header");
            return;
        }

        try {
            String token = authHeader.substring(7);
            Map<String, String> tokenDetails = jwtService.validateAndExtractTokenDetails(token);
            String username = tokenDetails.get("username");

            if (username == null || username.isEmpty()) {
                logger.error("Token validation failed: Missing username");
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: Invalid token");
                return;
            }

            logger.info("JWT token validated for username: [{}], URI: [{}], Method: [{}]",
                        username, requestUri, httpMethod);

            SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(username, null, null)
            );

            // CSRF validation handled by CsrfFilter. Just ensure we don't remove or regenerate tokens unnecessarily.

            logger.info("Successfully processed request URI: [{}], Method: [{}], Username: [{}], Session ID: [{}]",
                        requestUri, httpMethod, username, 
                        (request.getSession(false) != null ? request.getSession(false).getId() : "No session"));
        } catch (Exception ex) {
            logger.error("Authentication failed: {}", ex.getMessage(), ex);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: " + ex.getMessage());
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void logHeaders(HttpServletRequest request) {
        logger.info("Request Headers:");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            logger.info("Header [{}]: [{}]", headerName, headerValue);
        }
    }
}