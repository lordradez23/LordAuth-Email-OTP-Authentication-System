package com.lordradeez.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.lordradeez.entities.UserOtp;

public interface UserOTPRepository extends JpaRepository <UserOtp, Integer>{
	UserOtp findByOtp(String otp);
}
