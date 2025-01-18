package com.ascendpgp.customerlogin.utils.test;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.ascendpgp.customerlogin.utils.PasswordValidator;

class PasswordValidatorTest {

    @Test
    void testValidPasswords() {
        assertTrue(PasswordValidator.isValid("Test@123"), "Standard valid password");
        assertTrue(PasswordValidator.isValid("Complex@Password123"), "Complex valid password");
        assertTrue(PasswordValidator.isValid("Ab@12345"), "Minimum length valid password");
        assertTrue(PasswordValidator.isValid("Th!sIsV@lid123"), "Long valid password");
    }

    @Test
    void testInvalidPasswords() {
        // Missing uppercase
        assertFalse(PasswordValidator.isValid("test@123"), "Password without uppercase");

        // Missing lowercase
        assertFalse(PasswordValidator.isValid("TEST@123"), "Password without lowercase");

        // Missing number
        assertFalse(PasswordValidator.isValid("Test@abc"), "Password without number");

        // Missing special character
        assertFalse(PasswordValidator.isValid("Test1234"), "Password without special character");

        // Too short
        assertFalse(PasswordValidator.isValid("T@1a"), "Password too short");
    }

    @Test
    void testEdgeCases() {
        assertFalse(PasswordValidator.isValid(""), "Empty password");
        assertFalse(PasswordValidator.isValid(null), "Null password");
        assertFalse(PasswordValidator.isValid(" "), "Space only password");
        assertFalse(PasswordValidator.isValid("   "), "Multiple spaces password");
    }

    @Test
    void testPasswordsWithSpaces() {
        assertFalse(PasswordValidator.isValid("Test @123"), "Password with space in middle");
        assertFalse(PasswordValidator.isValid(" Test@123"), "Password with leading space");
        assertFalse(PasswordValidator.isValid("Test@123 "), "Password with trailing space");
    }
}