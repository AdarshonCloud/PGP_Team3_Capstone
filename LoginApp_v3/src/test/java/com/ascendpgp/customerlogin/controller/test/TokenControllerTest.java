package com.ascendpgp.customerlogin.controller.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.ascendpgp.customerlogin.controller.TokenController;
import com.ascendpgp.customerlogin.repository.BlacklistedTokenRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import io.jsonwebtoken.Claims;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TokenControllerTest {

    @Mock
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private Claims claims;

    @InjectMocks
    private TokenController tokenController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void blacklistToken_Success() {
        // Arrange
        String token = "valid-token";
        when(blacklistedTokenRepository.existsByToken(token)).thenReturn(false);
        doNothing().when(jwtService).blacklistToken(token);

        // Act
        ResponseEntity<Map<String, String>> response = tokenController.blacklistToken(token);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Token blacklisted successfully", response.getBody().get("message"));
        verify(jwtService).blacklistToken(token);
    }

    @Test
    void blacklistToken_AlreadyBlacklisted() {
        // Arrange
        String token = "already-blacklisted-token";
        when(blacklistedTokenRepository.existsByToken(token)).thenReturn(true);

        // Act
        ResponseEntity<Map<String, String>> response = tokenController.blacklistToken(token);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Token is already blacklisted", response.getBody().get("message"));
        verify(jwtService, never()).blacklistToken(token);
    }

    @Test
    void blacklistToken_NullOrEmpty() {
        // Test null token
        ResponseEntity<Map<String, String>> nullResponse = tokenController.blacklistToken(null);
        assertEquals(HttpStatus.BAD_REQUEST, nullResponse.getStatusCode());
        assertEquals("Token cannot be null or empty", nullResponse.getBody().get("error"));

        // Test empty token
        ResponseEntity<Map<String, String>> emptyResponse = tokenController.blacklistToken("");
        assertEquals(HttpStatus.BAD_REQUEST, emptyResponse.getStatusCode());
        assertEquals("Token cannot be null or empty", emptyResponse.getBody().get("error"));
    }

    @Test
    void blacklistToken_Error() {
        // Arrange
        String token = "error-token";
        when(blacklistedTokenRepository.existsByToken(token)).thenReturn(false);
        doThrow(new RuntimeException("Blacklist error")).when(jwtService).blacklistToken(token);

        // Act
        ResponseEntity<Map<String, String>> response = tokenController.blacklistToken(token);

        // Assert
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertTrue(response.getBody().get("error").contains("Failed to blacklist token"));
    }
}