package com.lordradeez.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "User")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column
    private String name;

    @Column(name = "Phone_num")
    private int phone;

    @Column(name = "email_id", unique = true)
    private String emailId;

    @Column(name = "password")
    private String password;

    /** Timestamp of the last successful login (post-OTP verification). */
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    /** Number of consecutive failed login attempts. Reset on successful login. */
    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts = 0;

    /** If non-null and in the future, the account is temporarily locked. */
    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    // ─── Constructors ────────────────────────────────────────────
    public User() {}

    public User(int id, String name, int phone, String emailId, String password) {
        this.id       = id;
        this.name     = name;
        this.phone    = phone;
        this.emailId  = emailId;
        this.password = password;
    }

    // ─── Getters & Setters ────────────────────────────────────────
    public int getId()              { return id; }
    public void setId(int id)       { this.id = id; }

    public String getName()              { return name; }
    public void   setName(String name)   { this.name = name; }

    public int  getPhone()           { return phone; }
    public void setPhone(int phone)  { this.phone = phone; }

    public String getEmailId()               { return emailId; }
    public void   setEmailId(String emailId) { this.emailId = emailId; }

    public String getPassword()                { return password; }
    public void   setPassword(String password) { this.password = password; }

    public LocalDateTime getLastLoginAt()                           { return lastLoginAt; }
    public void          setLastLoginAt(LocalDateTime lastLoginAt)  { this.lastLoginAt = lastLoginAt; }

    public int  getFailedAttempts()                    { return failedAttempts; }
    public void setFailedAttempts(int failedAttempts)  { this.failedAttempts = failedAttempts; }

    public LocalDateTime getLockedUntil()                        { return lockedUntil; }
    public void          setLockedUntil(LocalDateTime lockedUntil) { this.lockedUntil = lockedUntil; }

    /** Returns true if the account is currently within a lockout window. */
    public boolean isLocked() {
        return lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
    }
}
