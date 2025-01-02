package com.ascendpgp.creditcard.filters;

import com.ascendpgp.creditcard.utils.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtService jwtService;
    private final CsrfTokenRepository csrfTokenRepository;
    private final RestTemplate restTemplate;
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(JwtService jwtService, CsrfTokenRepository csrfTokenRepository, RestTemplate restTemplate) {
        this.jwtService = jwtService;
        this.csrfTokenRepository = csrfTokenRepository;
        this.restTemplate = restTemplate;
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
        logger.info("Processing request URI: [{}], Method: [{}]", requestUri, httpMethod);

        logHeaders(request);

        if (shouldSkipValidation(requestUri)) {
            logger.info("Skipping JWT/CSRF validation for URI: {}", requestUri);
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.error("Missing or invalid Authorization header.");
            sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: Missing or invalid Authorization header");
            return;
        }

        String token = authHeader.substring(7); // Extract token
        try {
            // Validate token blacklist
            String validationApiUrl = "http://localhost:8081/api/customer/token/validate?token=" + token;
            ResponseEntity<String> validationResponse = restTemplate.getForEntity(validationApiUrl, String.class);
            if (!validationResponse.getStatusCode().is2xxSuccessful()) {
                logger.error("Token is blacklisted or invalid. Response: {}", validationResponse.getBody());
                sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "Token is invalid or blacklisted.");
                return;
            }

            // Validate token and extract details
            Map<String, String> tokenDetails = jwtService.validateAndExtractTokenDetails(token);
            String username = tokenDetails.get("username");

            if (username == null || username.isEmpty()) {
                sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "Invalid token. Please log in again.");
                return;
            }

            logger.info("JWT token validated for username: [{}]", username);

            SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(username, null, null)
            );

        } catch (Exception ex) {
            logger.error("Authentication failed: {}", ex.getMessage(), ex);
            sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "Forbidden: Authentication failed.");
            return;
        }

        filterChain.doFilter(request, response);
    }
    
    /**
     * Helper method to send clean JSON error responses.
     */
    private void sendErrorResponse(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");

        // Use ObjectMapper to construct clean JSON response
        Map<String, String> errorResponse = Map.of("error", message);
        String jsonResponse = new ObjectMapper().writeValueAsString(errorResponse);

        response.getWriter().write(jsonResponse);
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