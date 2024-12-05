package com.ascendpgp.customerlogin.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import com.ascendpgp.customerlogin.model.CustomerEntity;

public interface CustomerRepository extends MongoRepository<CustomerEntity, String> {

    // Find a customer by username
    CustomerEntity findByUsername(String username);

    // Find a customer by email
    @Query("{ 'email' : { $regex: ?0, $options: 'i' } }")
    CustomerEntity findByEmail(String email);

    default CustomerEntity safeFindByEmail(String email) {
        CustomerEntity customer = findByEmail(email);
        System.out.println("Queried Email: " + email);
        System.out.println("Found Customer: " + customer);
        return customer;
    }

    // Find a customer by resetPasswordToken
    CustomerEntity findByResetPasswordToken(String resetPasswordToken);

    // Additional method (optional): Find a customer by verificationToken
    CustomerEntity findByVerificationToken(String token);
    
}
