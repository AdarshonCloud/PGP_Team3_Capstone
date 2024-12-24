package com.ascendpgp.customerlogin.utils;
import java.util.List;

import org.bson.Document;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;

public class PasswordHasher {
    private static final String MONGO_URI = "mongodb+srv://root:q2e0ilmWPlg8cH3Q@ascend.qgdyk.mongodb.net/?retryWrites=true&w=majority&appName=Ascend";
    private static final String DATABASE_NAME = "CCMS";
    private static final String COLLECTION_NAME = "Customer";

    public static void main(String[] args) {
        try (MongoClient mongoClient = MongoClients.create(MONGO_URI)) {
            MongoDatabase database = mongoClient.getDatabase(DATABASE_NAME);
            MongoCollection<Document> collection = database.getCollection(COLLECTION_NAME);

            // Initialize Spring Security's BCryptPasswordEncoder
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

            // Fetch all users from the collection
            List<Document> users = collection.find().into(new java.util.ArrayList<>());

            for (Document user : users) {
                String username = user.getString("username");
                String currentPassword = user.getString("password");

                if (currentPassword != null && !currentPassword.isEmpty()) {
                    if (isHashed(currentPassword)) {
                        System.out.println("Password already hashed for user: " + username);
                        continue; // Skip users whose passwords are already hashed
                    }

                    // Hash the password
                    String hashedPassword = passwordEncoder.encode(currentPassword);

                    // Update the password in the database
                    collection.updateOne(
                        Filters.eq("username", username),
                        Updates.set("password", hashedPassword)
                    );

                    System.out.println("Updated password for user: " + username);
                } else {
                    System.out.println("No password found for user: " + username);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Checks if the given password string is already hashed.
     *
     * @param password The password to check.
     * @return True if the password is hashed, false otherwise.
     */
    private static boolean isHashed(String password) {
        // BCrypt hashes start with $2a$, $2b$, or $2y$
        return password.startsWith("$2a$") || password.startsWith("$2b$") || password.startsWith("$2y$");
    }
}