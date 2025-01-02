package com.ascendpgp.customerlogin.controller.test;

import com.ascendpgp.customerlogin.controller.JwtController;
import com.ascendpgp.customerlogin.utils.JwtService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

class JwtControllerTest {

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private JwtController jwtController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testValidateToken_Success() {
        // Mock input and expected claims
        String token = "valid-token";
        Claims claims = mock(Claims.class);
        when(jwtService.extractClaims(token)).thenReturn(claims);
        when(claims.get("username", String.class)).thenReturn("testUser");
        when(claims.get("email", String.class)).thenReturn("test@example.com");

        // Invoke the controller method
        ResponseEntity<Map<String, String>> response = jwtController.validateToken(token);

        // Assertions
        assertNotNull(response);
        assertEquals(200, response.getStatusCode());
        assertEquals("testUser", response.getBody().get("username"));
        assertEquals("test@example.com", response.getBody().get("email"));

        // Verify interactions
        verify(jwtService, times(1)).extractClaims(token);
    }

    @Test
    void testValidateToken_Fallback() {
        // Mock input and simulate an exception
        String token = "faulty-token";
        when(jwtService.extractClaims(token)).thenThrow(new RuntimeException("Service error"));

        // Invoke the controller method and trigger fallback
        ResponseEntity<Map<String, String>> response = jwtController.validateTokenFallback(token, new RuntimeException("Service error"));

        // Assertions
        assertNotNull(response);
        assertEquals(400, response.getStatusCode());
        assertEquals("Token validation failed due to an error: Service error", response.getBody().get("error"));

        // Verify interactions
        verify(jwtService, never()).extractClaims(token); // Ensure primary method was not called again
    }

    @Test
    void testValidateToken_InvalidToken() {
        // Mock input and simulate invalid token
        String token = "invalid-token";
        when(jwtService.extractClaims(token)).thenThrow(new RuntimeException("Invalid token"));

        // Invoke the controller method and trigger fallback
        ResponseEntity<Map<String, String>> response = jwtController.validateTokenFallback(token, new RuntimeException("Invalid token"));

        // Assertions
        assertNotNull(response);
        assertEquals(400, response.getStatusCode());
        assertEquals("Token validation failed due to an error: Invalid token", response.getBody().get("error"));
    }
}