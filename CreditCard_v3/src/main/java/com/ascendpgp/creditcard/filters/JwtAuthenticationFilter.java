package com.ascendpgp.creditcard.filters;

import com.ascendpgp.creditcard.utils.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.HandlerExecutionChain;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtService jwtService;
    private final CsrfTokenRepository csrfTokenRepository;
    private final RestTemplate restTemplate;
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    // Include this in JwtAuthenticationFilter
    private final RequestMappingHandlerMapping handlerMapping;

    public JwtAuthenticationFilter(JwtService jwtService, CsrfTokenRepository csrfTokenRepository, RestTemplate restTemplate, RequestMappingHandlerMapping handlerMapping) {
        this.jwtService = jwtService;
        this.csrfTokenRepository = csrfTokenRepository;
        this.restTemplate = restTemplate;
        this.handlerMapping = handlerMapping;
    }

    private boolean shouldSkipValidation(String requestUri) {

        // Explicitly skip Actuator endpoints
        if (antPathMatcher.match("/actuator/**", requestUri)) {
            logger.info("Skipping validation for Actuator endpoint: {}", requestUri);
            return true;
        }

        // Other paths to skip
        return antPathMatcher.match("/api/customer/csrf-token", requestUri)
                || antPathMatcher.match("/v3/api-docs/**", requestUri)
                || antPathMatcher.match("/swagger-ui/**", requestUri)
                || antPathMatcher.match("/swagger-ui.html", requestUri)
                || antPathMatcher.match("/error", requestUri)
                || requestUri.equals("/error");
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

        // Check if the endpoint exists
        if (isNonExistentEndpoint(request)) {
            logger.warn("Non-existent endpoint detected: {}", requestUri);
            sendErrorResponse(response, HttpServletResponse.SC_NOT_FOUND,
                    "The endpoint you are trying to access does not exist. Please check the URL or contact support.");
            return;
        }

        // If the endpoint exists, continue with the filter chain
//        try {
//            filterChain.doFilter(request, response);
//        } catch (Exception ex) {
//            logger.error("Error during request processing: {}", ex.getMessage(), ex);
//            // Allow controller-specific exceptions to propagate
//            throw ex;
//        }

        // Skip validation for explicitly configured paths or non-existent endpoints
        if (shouldSkipValidation(requestUri)) {
            logger.info("Skipping JWT/CSRF validation for URI: {}", requestUri);
            filterChain.doFilter(request, response);
            return;
        }

        // Validate Authorization header
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

            logger.info("Sending token validation request to URL: {}", validationApiUrl);

            // Set headers for the request
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + token); // Optional, in case validate API requires it
            headers.set("Content-Type", "application/json");

            // Wrap the request in an HttpEntity
            HttpEntity<String> entity = new HttpEntity<>(headers);

            // Log the actual request details
            logger.info("Request Headers: {}", headers);

            // Make the RestTemplate call
            ResponseEntity<String> validationResponse = restTemplate.exchange(
                    validationApiUrl,
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            // Log the response details
            logger.info("Token validation response: Status Code: {}, Body: {}",
                    validationResponse.getStatusCode(),
                    validationResponse.getBody());

            // Check if the token is valid
            if (!validationResponse.getStatusCode().is2xxSuccessful()) {
                logger.error("Token validation failed with status: {}", validationResponse.getStatusCode());
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

            // Set authentication in SecurityContextHolder
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(username, null, null)
            );

        } catch (Exception ex) {
            logger.error("Authentication failed: {}", ex.getMessage(), ex);
            sendErrorResponse(response, HttpServletResponse.SC_FORBIDDEN, "Forbidden: Authentication failed.");
            return;
        }


        // If all checks pass, proceed with the filter chain
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

    /**
     * Helper method to check if the endpoint exists.
     */
    private boolean isNonExistentEndpoint(HttpServletRequest request) {
        String requestUri = request.getRequestURI();

        // Allow `/validate` endpoint
        if (requestUri.equals("*/api/customer/token/validate")) {
            return false;
        }

        if (requestUri.equals("*/api/customer/jwt/validate")) {
            return false;
        }

        // Explicitly allow Swagger-related paths
        if (antPathMatcher.match("/swagger-ui/**", requestUri) || antPathMatcher.match("/v3/api-docs/**", requestUri)) {
            logger.debug("Swagger endpoint detected: {}", requestUri);
            return false;
        }

        // Explicitly treat Actuator endpoints as valid
        if (antPathMatcher.match("/actuator/**", requestUri)) {
            logger.debug("Actuator endpoint detected: {}", requestUri);
            return false;
        }

        try {
            HandlerExecutionChain handler = handlerMapping.getHandler(request);

            // If no handler is found, it's a non-existent endpoint
            if (handler == null) {
                logger.warn("No handler found for [{}]. Marking as non-existent.", requestUri);
                logger.debug("HandlerMapping.bestMatchingHandler for [{}]: null", requestUri);
                return true;
            }
            logger.debug("HandlerMapping.bestMatchingHandler for [{}]: {}", requestUri, handler);
            return false;
        } catch (Exception ex) {
            logger.error("Error while checking if endpoint exists: {}", ex.getMessage(), ex);
            // Default to assuming the endpoint does not exist if there's an exception
            return true;
        }
    }
}