package com.ascendpgp.customerlogin.repository;

import com.ascendpgp.customerlogin.model.CreditCard;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface CreditCardRepository extends MongoRepository<CreditCard, String> {
    CreditCard findByUsername(String username);
}

