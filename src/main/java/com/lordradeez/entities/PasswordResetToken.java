package com.lordradeez.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Stores a one-time UUID token for password reset.
 * The token is emailed as a link and expires after 15 minutes.
 */
@Entity
@Table(name = "password_reset_token")
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(name = "token", nullable = false, unique = true)
    private String token;

    @Column(name = "user_id", nullable = false)
    private int userId;

    @Column(name = "expiry_time", nullable = false)
    private LocalDateTime expiryTime;

    @Column(name = "used", nullable = false)
    private boolean used = false;

    public PasswordResetToken() {}

    public PasswordResetToken(String token, int userId, LocalDateTime expiryTime) {
        this.token      = token;
        this.userId     = userId;
        this.expiryTime = expiryTime;
        this.used       = false;
    }

    // ─── Getters & Setters ────────────────────────────────────────
    public int    getId()                        { return id; }
    public void   setId(int id)                  { this.id = id; }

    public String getToken()                     { return token; }
    public void   setToken(String token)         { this.token = token; }

    public int    getUserId()                    { return userId; }
    public void   setUserId(int userId)          { this.userId = userId; }

    public LocalDateTime getExpiryTime()                         { return expiryTime; }
    public void          setExpiryTime(LocalDateTime expiryTime) { this.expiryTime = expiryTime; }

    public boolean isUsed()                      { return used; }
    public void    setUsed(boolean used)         { this.used = used; }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryTime);
    }
}
