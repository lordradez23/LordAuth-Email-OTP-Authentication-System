package com.lordradeez.services;

import java.time.LocalDateTime;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.lordradeez.entities.User;
import com.lordradeez.entities.UserOtp;
import com.lordradeez.repositories.UserOTPRepository;
import com.lordradeez.repositories.UserRepository;

@Service
public class UserService {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    UserRepository userRepo;

    @Autowired
    UserOTPRepository userOtpRepo;

    @Autowired
    JavaMailSender mailSender;

    public void register(User user) {
        // Hash the password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepo.save(user);
    }

    public boolean loginAndGenerateOTP(String emailId, String password) {
        User user = userRepo.findByEmailId(emailId);
        if (user == null) {
            return false;
        }

        // Compare BCrypt hashed password
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return false;
        }

        int otpNum = new Random().nextInt(100000, 1000000);
        String otp = String.valueOf(otpNum);

        UserOtp userOtp = new UserOtp();
        userOtp.setOtp(otp);
        userOtp.setUserId(user.getId());
        userOtp.setCreatedTime(LocalDateTime.now());
        userOtpRepo.save(userOtp);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmailId());
        message.setSubject("Your LordAuth OTP Code");
        message.setText("Hello " + user.getName() + ",\n\nYour OTP code is: " + otp + "\n\nThis code is valid for 1 minute.\n\n— LordAuth System");
        mailSender.send(message);
        return true;
    }

    public boolean verifyOtp(String otp) {
        UserOtp userOtp = userOtpRepo.findByOtp(otp);
        if (userOtp == null) {
            return false;
        }
        // Reject already-consumed OTPs (prevents replay attacks)
        if (userOtp.isUsed()) {
            return false;
        }
        LocalDateTime expiryTime = userOtp.getCreatedTime().plusMinutes(1);
        if (LocalDateTime.now().isAfter(expiryTime)) {
            return false;
        }
        // Mark the OTP as consumed so it cannot be reused
        userOtp.setUsed(true);
        userOtpRepo.save(userOtp);
        return true;
    }
}
