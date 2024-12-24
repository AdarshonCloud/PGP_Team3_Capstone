package com.ascendpgp.creditcard.repository;

import com.ascendpgp.creditcard.model.CreditCard;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CreditCardRepository extends MongoRepository<CreditCard, String>, CustomCreditCardRepository {

    /**
     * Fetch enabled and non-deleted credit cards for a user.
     */
    @Query("{ 'username': ?0, 'creditcards': { $elemMatch: { 'status': 'enabled', 'deleted': false } } }")
    Optional<CreditCard> findActiveCreditCardsByUsername(String username);

    /**
     * Query to find CreditCard by username.
     */
    @Query("{ 'username': ?0 }")
    Optional<CreditCard> findByUsername(String username);

    /**
     * Find a card by its encrypted card number in the nested creditcards array.
     */
    @Query(value = "{ 'creditcards.creditCardNumber': ?0 }", fields = "{ 'creditcards.$': 1 }")
    Optional<CreditCard> findByCreditCardNumber(String creditCardNumber);
}