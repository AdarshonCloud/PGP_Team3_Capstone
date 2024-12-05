package com.ascendpgp.customerlogin.controller;

import com.ascendpgp.customerlogin.model.CreditCard;
import com.ascendpgp.customerlogin.Service.CreditCardService;
// import com.ascendpgp.customerlogin.config.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/customer/creditcard")
public class CreditCardController {
    @Autowired
    private CreditCardService creditCardService;

    @PostMapping("/{username}")
    public ResponseEntity<CreditCard> addCreditCard(@PathVariable String username, @RequestBody CreditCard.CreditCardDetail creditCardDetail) {
        CreditCard updatedCreditCard = creditCardService.addCreditCard(username, creditCardDetail);
        return ResponseEntity.ok(updatedCreditCard);
    }

    @PutMapping("/{username}/{creditCardId}/toggle")
    public ResponseEntity<String> toggleCreditCardStatus(@PathVariable String username, @PathVariable int creditCardId) {
        creditCardService.toggleCreditCardStatus(username, creditCardId);
        return ResponseEntity.ok("Credit card status toggled successfully.");
    }
    
    @DeleteMapping("/{username}/{creditCardNumber}")
    public ResponseEntity<String> deleteCreditCard(@PathVariable String username, @PathVariable String creditCardNumber) {
        // Call the service to delete the credit card by marking it as deleted
        String result = creditCardService.deleteCreditCard(username, creditCardNumber);
        return ResponseEntity.ok(result);
    }
    
    // delete controller
//  @DeleteMapping("/{creditCardNumber}")
//  public ResponseEntity<String> deleteCreditCard(@PathVariable String creditCardNumber, HttpServletRequest request) {
//      // Retrieve the JWT token from the Authorization header
//      String token = request.getHeader("Authorization");
//      if (token == null || token.isEmpty()) {
//          return ResponseEntity.status(401).body("Authorization token is missing");
//      }
//
//      // Here you would validate the token, for now, assume it's valid
//      // Validate JWT (This is just a placeholder for actual JWT validation logic)
//
//      String username = "extracted-from-jwt"; // Extract username from JWT token (Implementation depends on JWT library)
//      
//      String result = creditCardService.deleteCreditCard(username, creditCardNumber);
//      return ResponseEntity.ok(result);
//  }
    
}

