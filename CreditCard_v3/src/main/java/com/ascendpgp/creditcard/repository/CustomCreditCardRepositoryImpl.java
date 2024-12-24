package com.ascendpgp.creditcard.repository;

import com.ascendpgp.creditcard.exception.CustomAddCardException;
import com.ascendpgp.creditcard.model.CreditCard;
import com.ascendpgp.creditcard.model.CreditCard.CardDetails;
import com.ascendpgp.creditcard.utils.EncryptionUtil;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.result.UpdateResult;

import org.bson.Document;
import org.bson.conversions.Bson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.aggregation.Aggregation;
import org.springframework.data.mongodb.core.aggregation.AggregationResults;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class CustomCreditCardRepositoryImpl implements CustomCreditCardRepository {

    private static final Logger logger = LoggerFactory.getLogger(CustomCreditCardRepositoryImpl.class);

    @Autowired
    private MongoTemplate mongoTemplate;
    
    @Autowired
    private EncryptionUtil EncryptionUtil; // Inject EncryptionUtil

    @Override
    public void addCreditCard(String username, CardDetails cardDetails) {
        logger.info("Executing addCreditCard for user: {}", username);

        try {
            // Encrypt the card number if not already encrypted
            if (!EncryptionUtil.isEncrypted(cardDetails.getCreditCardNumber())) {
                cardDetails.setCreditCardNumber(EncryptionUtil.encrypt(cardDetails.getCreditCardNumber()));
            }

            // Query to find the user document
            Query query = new Query(Criteria.where("username").is(username));
            Update update = new Update().push("creditcards", cardDetails);

            // Perform the update
            UpdateResult result = mongoTemplate.updateFirst(query, update, "CreditCard");

            if (result.getMatchedCount() == 0) {
                logger.warn("No matching user document found for username: {}. Creating a new document.", username);

                // Create a new document if user not found
                CreditCard newCreditCard = new CreditCard();
                newCreditCard.setUsername(username);
                newCreditCard.setCreditcards(List.of(cardDetails));

                mongoTemplate.save(newCreditCard, "CreditCard");
                logger.info("Created a new document for user: {} in CreditCard collection.", username);
            } else if (result.getModifiedCount() == 0) {
                logger.error("Failed to add credit card for user: {}. No modification occurred.", username);
                throw new CustomAddCardException("Failed to add credit card. No modification occurred in the existing document.");
            }

            logger.info("Credit card successfully added for user: {}", username);
        } catch (CustomAddCardException e) {
            logger.warn("AddCreditCard process completed with warnings for user: {}", username, e);
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error in addCreditCard for user: {}", username, e);
            throw new CustomAddCardException("An unexpected error occurred while adding the card.", e);
        }
    }
    
    
    // Soft Delete Credit Card
    @Override
    public void softDeleteCreditCard(String username, int creditCardId, String creditCardNumber) {
        logger.info("Soft deleting credit card for username: {}, creditCardId: {}, creditCardNumber: {}", username, creditCardId, creditCardNumber);

        try {
            // Fetch all active credit cards for the user
            List<CreditCard.CardDetails> userCards = findActiveCreditCards(username);

            if (userCards == null || userCards.isEmpty()) {
                logger.error("No active credit cards found for username: {}", username);
                throw new RuntimeException("No active credit cards found for the user.");
            }

            // Match the card using card number and ID, decrypt if necessary
            Optional<CreditCard.CardDetails> matchingCard = userCards.stream()
                .filter(card -> {
                    try {
                        String storedCardNumber = card.getCreditCardNumber();
                        if (EncryptionUtil.isEncrypted(storedCardNumber)) {
                            storedCardNumber = EncryptionUtil.decrypt(storedCardNumber);
                        }
                        return storedCardNumber.equals(creditCardNumber) && card.getCreditCardId() == creditCardId;
                    } catch (Exception e) {
                        logger.error("Error decrypting card number for comparison. Error: {}", e.getMessage());
                        return false;
                    }
                })
                .findFirst();

            if (matchingCard.isEmpty()) {
                logger.error("No matching credit card found for username: {}, creditCardId: {}, creditCardNumber: {}", username, creditCardId, creditCardNumber);
                throw new RuntimeException("Credit card not found.");
            }

            // Proceed with soft delete
            CreditCard.CardDetails cardDetails = matchingCard.get();

            if (cardDetails.isDeleted()) {
                logger.warn("Credit card is already soft-deleted. Username: {}, CreditCardId: {}", username, creditCardId);
                throw new RuntimeException("Credit card is already deleted.");
            }

            cardDetails.setDeleted(true);
            cardDetails.setStatus("disabled");

            // Update in the database
            Query query = new Query(Criteria.where("username").is(username)
                                            .and("creditcards.creditCardId").is(creditCardId));
            Update update = new Update()
                .set("creditcards.$.deleted", true)
                .set("creditcards.$.status", "disabled");

            UpdateResult result = mongoTemplate.updateFirst(query, update, CreditCard.class);

            if (result.getMatchedCount() == 0) {
                logger.error("Failed to update the credit card in the database. Username: {}, CreditCardId: {}", username, creditCardId);
                throw new RuntimeException("Failed to update the credit card.");
            }

            logger.info("Successfully soft-deleted credit card for username: {}, creditCardId: {}, creditCardNumber: {}", username, creditCardId, creditCardNumber);

        } catch (Exception e) {
            logger.error("Error executing softDeleteCreditCard for username: {}, creditCardId: {}, creditCardNumber: {}", username, creditCardId, creditCardNumber, e);
            throw new RuntimeException("Failed to soft-delete credit card.", e);
        }
    }
    
    @Override
    public void updateCreditCard(String username, Integer creditCardId, CreditCard.CardDetails cardDetails) {
        logger.info("Updating credit card for username: {}, creditCardId: {}", username, creditCardId);

        try {
            MongoCollection<Document> collection = mongoTemplate.getDb().getCollection("CreditCard");

            // Define the filter for the username
            Bson filter = Filters.eq("username", username);

            // If the credit card number is encrypted, handle both plain and encrypted values
            String encryptedCardNumber = EncryptionUtil.encrypt(cardDetails.getCreditCardNumber());
            Bson cardFilter = Filters.or(
                Filters.eq("creditcards.creditCardNumber", cardDetails.getCreditCardNumber()), // Plain text match
                Filters.eq("creditcards.creditCardNumber", encryptedCardNumber) // Encrypted match
            );

            // Create the update document with dynamic fields based on the cardDetails
            Document updateDocument = new Document();
            if (cardDetails.getStatus() != null) {
                updateDocument.append("creditcards.$[card].status", cardDetails.getStatus());
            }
            if (cardDetails.isDeleted() != null) { // Ensure deleted is not null
                updateDocument.append("creditcards.$[card].deleted", cardDetails.isDeleted());
            }

            Bson update = new Document("$set", updateDocument);

            // Use arrayFilters to match the specific credit card by ID
            UpdateOptions options = new UpdateOptions().arrayFilters(List.of(
                Filters.eq("card.creditCardId", creditCardId)
            ));

            // Execute the update
            UpdateResult result = collection.updateOne(filter, update, options);

            if (result.getMatchedCount() == 0) {
                logger.error("No matching credit card found for username: {}, creditCardId: {}", username, creditCardId);
                throw new RuntimeException("No matching credit card found for update.");
            }
            if (result.getModifiedCount() == 0) {
                logger.warn("No fields were updated for credit card with ID: {}", creditCardId);
            }

            logger.info("Successfully updated credit card for creditCardId: {}", creditCardId);

        } catch (Exception e) {
            logger.error("Error updating credit card for username: {}, creditCardId: {}", username, creditCardId, e);
            throw new RuntimeException("Failed to update credit card", e);
        }
    }
    
    @Override
    public void updateCreditCardStatus(String username, int creditCardId, String creditCardNumber, boolean deleted, String newStatus) {
        logger.info("Updating credit card status for username: {}, creditCardId: {}, creditCardNumber: {}, newStatus: {}", username, creditCardId, creditCardNumber, newStatus);

        try {
            MongoCollection<Document> collection = mongoTemplate.getDb().getCollection("CreditCard");

            // Define the filter for the username
            Bson filter = Filters.eq("username", username);

            // If the credit card is encrypted, we need to check the encrypted value
            String encryptedCardNumber = EncryptionUtil.encrypt(creditCardNumber);
            Bson cardFilter = Filters.or(
                Filters.eq("creditcards.creditCardNumber", creditCardNumber), // This is for plain text match
                Filters.eq("creditcards.creditCardNumber", encryptedCardNumber) // Encrypted card match
            );

            Bson update = new Document("$set", new Document("creditcards.$[card].status", newStatus));

            // Use arrayFilters to match the credit card with the given ID, card number and ensure it's not deleted
            UpdateOptions options = new UpdateOptions().arrayFilters(List.of(
                Filters.and(
                    Filters.eq("card.creditCardId", creditCardId),
                    Filters.eq("card.deleted", false) // Ensure the card is not soft-deleted
                )
            ));

            // Execute the update
            UpdateResult result = collection.updateOne(filter, update, options);

            if (result.getMatchedCount() == 0) {
                logger.error("No matching credit card found for username: {}, creditCardId: {}, creditCardNumber: {}", username, creditCardId, creditCardNumber);
                throw new RuntimeException("No matching credit card found for update.");
            }
            if (result.getModifiedCount() == 0) {
                logger.warn("Card status was not updated for cardId: {}, cardNumber: {}", creditCardId, creditCardNumber);
            }

            logger.info("Successfully updated card status for cardId: {}, cardNumber: {}", creditCardId, creditCardNumber);

        } catch (Exception e) {
            logger.error("Error updating credit card status for username: {}, creditCardId: {}", username, creditCardId, e);
            throw new RuntimeException("Failed to update credit card status", e);
        }
    }

    // Find All Active Credit Cards
    @Override
    public List<CardDetails> findActiveCreditCards(String username) {
        logger.info("Executing findActiveCreditCards for username: {}", username);

        try {
            Aggregation aggregation = Aggregation.newAggregation(
                Aggregation.match(Criteria.where("username").is(username)),
                Aggregation.project("creditcards")
            );

            AggregationResults<Document> results = mongoTemplate.aggregate(aggregation, "CreditCard", Document.class);
            List<Document> documents = results.getMappedResults();

            if (documents.isEmpty()) {
                logger.info("No credit cards found for username: {}", username);
                return List.of();
            }

            List<CardDetails> activeCards = new ArrayList<>();
            for (Document document : documents) {
                List<Document> creditCards = (List<Document>) document.get("creditcards");
                if (creditCards != null) {
                    for (Document cardDoc : creditCards) {
                        CardDetails cardDetails = mapToCardDetails(cardDoc);

                        // Filter active (not deleted) cards
                        if (cardDetails != null && !cardDetails.isDeleted()) {
                            // Dynamically mask the decrypted credit card number
                            try {
                                if (EncryptionUtil.isEncrypted(cardDetails.getCreditCardNumber())) {
                                    String decryptedCardNumber = EncryptionUtil.decrypt(cardDetails.getCreditCardNumber());
                                    cardDetails.setCreditCardNumber(maskCardNumber(decryptedCardNumber));
                                } else {
                                    cardDetails.setCreditCardNumber(maskCardNumber(cardDetails.getCreditCardNumber()));
                                }
                            } catch (Exception e) {
                                logger.warn("Error decrypting or masking card number: {}", e.getMessage());
                                cardDetails.setCreditCardNumber("XXXXXXXXXXXX****"); // Default masking if decryption fails
                            }
                            activeCards.add(cardDetails);
                        }
                    }
                }
            }
            return activeCards;
        } catch (Exception e) {
            logger.error("Error executing findActiveCreditCards", e);
            throw new RuntimeException("Failed to fetch active credit cards", e);
        }
    }
    
    // Find Credit Card by Number
    @Override
    public Optional<CardDetails> findCardDetailsByNumber(String username, String cardNumber) {
        logger.info("Executing findCardDetailsByNumber for username: {}, cardNumber: {}", username, cardNumber);

        try {
            Query query = new Query(Criteria.where("username").is(username));
            List<Document> documents = mongoTemplate.find(query, Document.class, "CreditCard");

            for (Document document : documents) {
                List<Document> creditCards = (List<Document>) document.get("creditcards");
                if (creditCards != null) {
                    for (Document cardDoc : creditCards) {
                        CardDetails cardDetails = mapToCardDetails(cardDoc);

                        if (cardDetails != null) {
                            String decryptedCardNumber = null;
                            try {
                                if (EncryptionUtil.isEncrypted(cardDetails.getCreditCardNumber())) {
                                    decryptedCardNumber = EncryptionUtil.decrypt(cardDetails.getCreditCardNumber());
                                } else {
                                    decryptedCardNumber = cardDetails.getCreditCardNumber();
                                }
                                if (decryptedCardNumber.equals(cardNumber)) {
                                    cardDetails.setCreditCardNumber(maskCardNumber(decryptedCardNumber)); // Masked dynamically
                                    return Optional.of(cardDetails);
                                }
                            } catch (Exception e) {
                                logger.warn("Error decrypting or matching card number: {}", e.getMessage());
                            }
                        }
                    }
                }
            }
            return Optional.empty();
        } catch (Exception e) {
            logger.error("Error executing findCardDetailsByNumber for username: {}, cardNumber: {}", username, cardNumber, e);
            throw new RuntimeException("Failed to find credit card by number", e);
        }
    }
    
    // Mapping Credit Card Details
    private CreditCard.CardDetails mapToCardDetails(Document cardDoc) {
        try {
            CreditCard.CardDetails cardDetails = new CreditCard.CardDetails();
            cardDetails.setCreditCardId(cardDoc.getInteger("creditCardId")); // Ensure Integer
            cardDetails.setCreditCardNumber(cardDoc.getString("creditCardNumber"));
            cardDetails.setExpiryMonth(cardDoc.getInteger("expiryMonth", 0)); // Default to 0 if null
            cardDetails.setExpiryYear(cardDoc.getInteger("expiryYear", 0));   // Default to 0 if null
            
            // Handle cvv as Integer
            Object cvv = cardDoc.get("cvv");
            if (cvv instanceof Integer) {
                cardDetails.setCvv((Integer) cvv);
            } else if (cvv instanceof String) {
                cardDetails.setCvv(Integer.parseInt((String) cvv));
            } else {
                cardDetails.setCvv(0); // Default if null or invalid
            }

            cardDetails.setWireTransactionVendor(cardDoc.getString("wireTransactionVendor"));
            cardDetails.setStatus(cardDoc.getString("status"));
            cardDetails.setDeleted(cardDoc.getBoolean("deleted", false));
            return cardDetails;
        } catch (Exception e) {
            logger.warn("Failed to parse card details for cardDoc: {}. Error: {}", cardDoc, e.getMessage());
            return null;
        }
    }
    

    
 // Masking Credit Card method
    private String maskCardNumber(String cardNumber) {
        // Handle null or empty input
        if (cardNumber == null || cardNumber.isEmpty()) {
            logger.warn("Card number is null or empty, returning default masked value.");
            return "XXXXXXXXXXXX****";
        }

        // Check for standard card length (16 or more digits)
        if (cardNumber.length() >= 16) {
            // Mask all but the last 4 digits
            return "XXXXXXXXXXXX" + cardNumber.substring(cardNumber.length() - 4);
        }

        // Handle unexpected card number formats
        logger.warn("Unexpected card number length: {}. Returning default masked value.", cardNumber.length());
        return "XXXXXXXXXXXX****"; // Default for invalid or short card numbers
    }
}