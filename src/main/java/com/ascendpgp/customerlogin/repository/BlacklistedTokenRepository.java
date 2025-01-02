package com.ascendpgp.customerlogin.repository;

import com.ascendpgp.customerlogin.model.BlacklistedToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BlacklistedTokenRepository extends MongoRepository<BlacklistedToken, String> {
    boolean existsByToken(String token);
}