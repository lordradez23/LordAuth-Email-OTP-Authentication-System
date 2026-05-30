package com.lordradeez.entities;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table
public class UserOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int otpId;

    @Column
    private String otp;

    @Column
    private int userId;

    @Column
    private LocalDateTime createdTime;

    @Column(nullable = false)
    private boolean used = false;

    public UserOtp() {}

    public UserOtp(int otpId, String otp, int userId, LocalDateTime createdTime) {
        this.otpId = otpId;
        this.otp = otp;
        this.userId = userId;
        this.createdTime = createdTime;
        this.used = false;
    }

    public int getOtpId() { return otpId; }
    public void setOtpId(int otpId) { this.otpId = otpId; }

    public String getOtp() { return otp; }
    public void setOtp(String otp) { this.otp = otp; }

    public int getUserId() { return userId; }
    public void setUserId(int userId) { this.userId = userId; }

    public LocalDateTime getCreatedTime() { return createdTime; }
    public void setCreatedTime(LocalDateTime createdTime) { this.createdTime = createdTime; }

    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }
}
