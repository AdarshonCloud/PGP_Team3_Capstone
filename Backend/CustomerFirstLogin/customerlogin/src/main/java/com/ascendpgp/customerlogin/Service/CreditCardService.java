package com.ascendpgp.customerlogin.Service;


import com.ascendpgp.customerlogin.model.CreditCard;
import com.ascendpgp.customerlogin.model.CustomerEntity; // made changes here
import com.ascendpgp.customerlogin.repository.CreditCardRepository;
import com.ascendpgp.customerlogin.repository.CustomerRepository; // need to check the code here as well
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CreditCardService {

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private CreditCardRepository creditCardRepository;

    public CreditCard addCreditCard(String username, CreditCard.CreditCardDetail creditCardDetail) {
    	CustomerEntity customer = customerRepository.findByUsername(username);
        if (customer == null) {
            throw new RuntimeException("Customer not found");
        }

        CreditCard creditCard = creditCardRepository.findByUsername(username);
        if (creditCard == null) {
            creditCard = new CreditCard();
            creditCard.setUsername(username);
            creditCard.setNameOnTheCard(customer.getFirstName() + " " + customer.getLastName());
            creditCard.setCreditcards(new ArrayList<>());
        }

        creditCard.getCreditcards().add(creditCardDetail);
        return creditCardRepository.save(creditCard);
    }

    public void toggleCreditCardStatus(String username, int creditCardId) {
        CreditCard creditCard = creditCardRepository.findByUsername(username);
        if (creditCard != null) {
            for (CreditCard.CreditCardDetail card : creditCard.getCreditcards()) {
                if (card.getCreditCardId() == creditCardId) {
                    card.setStatus(card.getStatus().equals("enabled") ? "disabled" : "enabled");
                    break;
                }
            }
            creditCardRepository.save(creditCard);
        }
    }
    
    //Soft delete the credit card (mark as deleted with flag)  
    public String deleteCreditCard(String username, String creditCardNumber) {
        CreditCard creditCard = creditCardRepository.findByUsername(username);
        if (creditCard != null) {
            for (CreditCard.CreditCardDetail card : creditCard.getCreditcards()) {
                if (card.getCreditCardNumber().equals(creditCardNumber)) {
                    if (!card.isDeleted()) {
                        card.setDeleted(true);
                        creditCardRepository.save(creditCard);
                        return "Card deleted successfully";
                    } else {
                        return "Card is already marked as deleted";
                    }
                }
            }
        }
        return "Credit card not found";
    }
}

