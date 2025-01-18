package com.ascendpgp.customerlogin.utils.test;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.ascendpgp.customerlogin.repository.BlacklistedTokenRepository;
import com.ascendpgp.customerlogin.utils.JwtService;
import com.ascendpgp.customerlogin.model.BlacklistedToken;
import java.util.Map;

class JwtServiceTest {

    @Mock
    private BlacklistedTokenRepository blacklistedTokenRepository;

    private JwtService jwtService;
    private final String SECRET_KEY = "Rkpztddz+eXq3p1nzslnfy+1hnqoPf8MFyzHyzSWvNdvG295SUL7ZGZtNAkIw9Qfov4EiTGSxAVqobtqg0l2kg==";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        jwtService = new JwtService(SECRET_KEY, blacklistedTokenRepository);
    }

    @Test
    void generateAndValidateToken_Success() {
        String email = "test@example.com";
        String username = "testuser";

        String token = jwtService.generateToken(email, username);

        assertNotNull(token);
        assertTrue(jwtService.validateToken(token));
    }

    @Test
    void extractUserDetails_Success() {
        String email = "test@example.com";
        String username = "testuser";

        String token = jwtService.generateToken(email, username);
        Map<String, String> details = jwtService.extractUserDetails(token);

        assertEquals(email, details.get("email"));
        assertEquals(username, details.get("username"));
    }

    @Test
    void blacklistToken_Success() {
        String token = jwtService.generateToken("test@example.com", "testuser");

        jwtService.blacklistToken(token);

        verify(blacklistedTokenRepository, times(1)).save(any(BlacklistedToken.class));
    }

    @Test
    void validateToken_BlacklistedToken() {
        String token = jwtService.generateToken("test@example.com", "testuser");
        when(blacklistedTokenRepository.existsByToken(token)).thenReturn(true);

        assertFalse(jwtService.validateToken(token));
    }

    @Test
    void validateToken_InvalidToken() {
        assertFalse(jwtService.validateToken("invalid-token"));
    }

    @Test
    void validateToken_NullOrEmpty() {
        assertFalse(jwtService.validateToken(null));
        assertFalse(jwtService.validateToken(""));
    }

    @Test
    void extractEmail_Success() {
        String email = "test@example.com";
        String username = "testuser";
        String token = jwtService.generateToken(email, username);

        assertEquals(email, jwtService.extractEmail(token));
    }

    @Test
    void extractUsername_Success() {
        String email = "test@example.com";
        String username = "testuser";
        String token = jwtService.generateToken(email, username);

        assertEquals(username, jwtService.extractUsername(token));
    }
}