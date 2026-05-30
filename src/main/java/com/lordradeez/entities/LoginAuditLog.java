package com.lordradeez.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Records every login attempt outcome for security auditing.
 * Captures: email, IP address, outcome, and timestamp.
 */
@Entity
@Table(name = "login_audit_log")
public class LoginAuditLog {

    public enum Outcome { SUCCESS, FAIL, LOCKED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "ip_address")
    private String ipAddress;

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false)
    private Outcome outcome;

    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    public LoginAuditLog() {}

    public LoginAuditLog(String email, String ipAddress, Outcome outcome) {
        this.email     = email;
        this.ipAddress = ipAddress;
        this.outcome   = outcome;
        this.timestamp = LocalDateTime.now();
    }

    // ─── Getters & Setters ────────────────────────────────────────
    public Long   getId()                  { return id; }
    public void   setId(Long id)           { this.id = id; }

    public String getEmail()               { return email; }
    public void   setEmail(String email)   { this.email = email; }

    public String getIpAddress()                       { return ipAddress; }
    public void   setIpAddress(String ipAddress)       { this.ipAddress = ipAddress; }

    public Outcome getOutcome()                { return outcome; }
    public void    setOutcome(Outcome outcome) { this.outcome = outcome; }

    public LocalDateTime getTimestamp()                        { return timestamp; }
    public void          setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}
