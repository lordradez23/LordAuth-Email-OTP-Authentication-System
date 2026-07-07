package com.lordradeez.repositories;

import com.lordradeez.entities.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, Integer> {
    EmailVerificationToken findByToken(String token);
    
    @org.springframework.transaction.annotation.Transactional
    void deleteByUserId(int userId);
}
