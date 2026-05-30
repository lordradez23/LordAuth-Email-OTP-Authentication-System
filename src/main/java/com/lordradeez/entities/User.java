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

    public LocalDateTime getLastLoginAt()                        { return lastLoginAt; }
    public void          setLastLoginAt(LocalDateTime lastLoginAt) { this.lastLoginAt = lastLoginAt; }
}
