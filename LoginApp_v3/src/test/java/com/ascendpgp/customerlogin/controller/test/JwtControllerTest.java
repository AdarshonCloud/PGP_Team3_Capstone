package com.ascendpgp.customerlogin.controller.test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;

import com.ascendpgp.customerlogin.controller.JwtController;
import com.ascendpgp.customerlogin.utils.JwtService;
import io.jsonwebtoken.Claims;

import java.util.Map;

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
        String token = "valid-token";
        Claims claims = mock(Claims.class);

        when(jwtService.extractClaims(token)).thenReturn(claims);
        when(claims.get("username", String.class)).thenReturn("testUser");
        when(claims.get("email", String.class)).thenReturn("test@example.com");

        ResponseEntity<Map<String, String>> response = jwtController.validateToken(token);

        assertNotNull(response);
        assertEquals(200, response.getStatusCodeValue());
        assertTrue(response.getStatusCode().is2xxSuccessful());
    }

    @Test
    void testValidateToken_Fallback() {
        String token = "invalid-token";
        RuntimeException ex = new RuntimeException("Token validation failed");

        ResponseEntity<Map<String, String>> response =
                jwtController.validateTokenFallback(token, ex);

        assertNotNull(response);
        assertEquals(400, response.getStatusCodeValue());
        assertTrue(response.getStatusCode().is4xxClientError());
    }
}