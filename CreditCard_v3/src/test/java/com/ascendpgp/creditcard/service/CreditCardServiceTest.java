package com.ascendpgp.creditcard.service;

import com.ascendpgp.creditcard.model.CreditCard;
import com.ascendpgp.creditcard.model.CreditCardRequest;
import com.ascendpgp.creditcard.repository.CreditCardRepository;
import com.ascendpgp.creditcard.repository.CustomCreditCardRepository;
import com.ascendpgp.creditcard.utils.EncryptionUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CreditCardServiceTest {

    @InjectMocks
    private CreditCardService creditCardService;

    @Mock
    private CreditCardRepository creditCardRepository;

    @Mock
    private CustomCreditCardRepository customCreditCardRepository;

    @Mock
    private EncryptionUtil encryptionUtil;

    @Mock
    private FallbackService fallbackService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void addCreditCard_ValidInputs_ShouldAddCreditCard() {
        String username = "testuser";
        CreditCardRequest request = new CreditCardRequest();
        request.setCardNumber("4111111111111111");
        request.setExpiryMonth(12);
        request.setExpiryYear(25);
        request.setWireTransactionVendor("Visa");
        request.setCvv(123);

        CreditCard.CardDetails cardDetails = new CreditCard.CardDetails();
        cardDetails.setCreditCardNumber("4111111111111111");

        CreditCard creditCard = new CreditCard();
        creditCard.setUsername(username);

        when(creditCardRepository.findById(username)).thenReturn(Optional.of(creditCard));
        when(creditCardRepository.save(any(CreditCard.class))).thenReturn(creditCard);

        CreditCard.CardDetails result = creditCardService.addCreditCard(username, request);

        assertNotNull(result);
        verify(creditCardRepository, times(1)).save(any(CreditCard.class));
    }

    @Test
    void addCreditCard_Fallback_ShouldTriggerFallback() {
        String username = "testuser";
        CreditCardRequest request = new CreditCardRequest();
        request.setCardNumber("invalid");

        when(fallbackService.addCreditCardFallback(eq(username), eq(request), any(Throwable.class)))
                .thenReturn(new CreditCard.CardDetails());

        CreditCard.CardDetails result = creditCardService.addCreditCard(username, request);

        assertNotNull(result);
        verify(fallbackService, times(1)).addCreditCardFallback(eq(username), eq(request), any(Throwable.class));
    }

    @Test
    void getActiveCreditCards_ValidUsername_ShouldReturnActiveCards() {
        String username = "testuser";
        CreditCard.CardDetails activeCard = new CreditCard.CardDetails();
        activeCard.setCreditCardNumber("4111111111111111");
        activeCard.setStatus("enabled");
        activeCard.setDeleted(false);

        when(customCreditCardRepository.findActiveCreditCards(username)).thenReturn(List.of(activeCard));

        List<CreditCard.CardDetails> result = creditCardService.getActiveCreditCards(username);

        assertNotNull(result);
        assertFalse(result.isEmpty());
        verify(customCreditCardRepository, times(1)).findActiveCreditCards(username);
    }

    @Test
    void getActiveCreditCards_Fallback_ShouldTriggerFallback() {
        String username = "testuser";

        when(fallbackService.getActiveCreditCardsFallback(eq(username), any(Throwable.class)))
                .thenReturn(Collections.emptyList());

        List<CreditCard.CardDetails> result = creditCardService.getActiveCreditCards(username);

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(fallbackService, times(1)).getActiveCreditCardsFallback(eq(username), any(Throwable.class));
    }

    @Test
    void toggleCreditCardStatus_ValidDetails_ShouldUpdateStatus() {
        // Arrange
        String username = "testuser";
        Integer creditCardId = 5;
        String creditCardNumber = "4111111111111111";
        String newStatus = "disabled";

        doNothing().when(customCreditCardRepository).updateCreditCardStatus(username, creditCardId, creditCardNumber, false, newStatus);

        // Act
        creditCardService.toggleCreditCardStatus(username, creditCardNumber) ;

        // Assert
        verify(customCreditCardRepository, times(1)).updateCreditCardStatus(username, creditCardId, creditCardNumber, false, newStatus);
    }

    @Test
    void toggleCreditCardStatus_Fallback_ShouldTriggerFallback() {
        // Arrange
        String username = "testuser";
        Integer creditCardId = 5;
        String creditCardNumber = "4111111111111111";
        String newStatus = "disabled";

        // Simulate an exception in the repository layer
        doThrow(new RuntimeException("Database connection error")).when(customCreditCardRepository)
                .updateCreditCardStatus(username, creditCardId, creditCardNumber, false, newStatus);

        // Mock the fallback behavior
        doNothing().when(fallbackService).toggleCreditCardFallback(eq(username), eq(creditCardNumber), any(Throwable.class));

        // Act
        creditCardService.toggleCreditCardStatus(username, creditCardNumber);

        // Assert
        verify(customCreditCardRepository, times(1)).updateCreditCardStatus(username, creditCardId, creditCardNumber, false, newStatus);
        verify(fallbackService, times(1)).toggleCreditCardFallback(eq(username), eq(creditCardNumber), any(Throwable.class));
    }

    @Test
    void softDeleteCreditCard_ValidNumber_ShouldMarkAsDeleted() {
        String username = "testuser";
        String creditCardNumber = "4111111111111111";
        CreditCard.CardDetails cardDetails = new CreditCard.CardDetails();
        cardDetails.setStatus("enabled");
        cardDetails.setDeleted(false);

        CreditCard creditCard = new CreditCard();
        creditCard.setUsername(username);
        creditCard.setCreditcards(List.of(cardDetails));

        when(creditCardRepository.findById(username)).thenReturn(Optional.of(creditCard));

        creditCardService.softDeleteCreditCard(username, creditCardNumber);

        assertEquals("deleted", cardDetails.getStatus());
        assertTrue(cardDetails.isDeleted());
        verify(creditCardRepository, times(1)).save(creditCard);
    }


    @Test
    void softDeleteCreditCard_Fallback_ShouldTriggerFallback() {
        String username = "testuser";
        String creditCardNumber = "invalid";

        doNothing().when(fallbackService).softDeleteCreditCardFallback(eq(username), eq(creditCardNumber), any(Throwable.class));

        creditCardService.softDeleteCreditCard(username, creditCardNumber);

        verify(fallbackService, times(1)).softDeleteCreditCardFallback(eq(username), eq(creditCardNumber), any(Throwable.class));
    }
}