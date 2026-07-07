package com.lordradeez.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "email_verification_token")
public class EmailVerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, unique = true)
    private String token;

    @Column(name = "user_id", nullable = false)
    private int userId;

    @Column(name = "expiry_time", nullable = false)
    private LocalDateTime expiryTime;

    public EmailVerificationToken() {}

    public EmailVerificationToken(String token, int userId) {
        this.token = token;
        this.userId = userId;
        this.expiryTime = LocalDateTime.now().plusHours(24);
    }

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public LocalDateTime getExpiryTime() { return expiryTime; }
    public void setExpiryTime(LocalDateTime expiryTime) { this.expiryTime = expiryTime; }
}
