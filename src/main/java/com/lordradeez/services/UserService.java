package com.lordradeez.services;

import java.time.LocalDateTime;
import java.util.Random;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.lordradeez.entities.User;
import com.lordradeez.entities.UserOtp;
import com.lordradeez.repositories.UserOTPRepository;
import com.lordradeez.repositories.UserRepository;

import jakarta.mail.internet.MimeMessage;

@Service
public class UserService {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Autowired
    UserRepository userRepo;

    @Autowired
    UserOTPRepository userOtpRepo;

    @Autowired
    JavaMailSender mailSender;

    // ─── Registration ─────────────────────────────────────────────
    public void register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepo.save(user);
    }

    // ─── Login + OTP Generation ───────────────────────────────────
    public boolean loginAndGenerateOTP(String emailId, String password) {
        User user = userRepo.findByEmailId(emailId);
        if (user == null) return false;
        if (!passwordEncoder.matches(password, user.getPassword())) return false;

        String otp = String.valueOf(new Random().nextInt(100000, 1000000));

        UserOtp userOtp = new UserOtp();
        userOtp.setOtp(otp);
        userOtp.setUserId(user.getId());
        userOtp.setCreatedTime(LocalDateTime.now());
        userOtpRepo.save(userOtp);

        sendOtpEmail(user.getEmailId(), user.getName(), otp);
        return true;
    }

    // ─── Resend OTP ───────────────────────────────────────────────
    public boolean resendOtp(String emailId) {
        User user = userRepo.findByEmailId(emailId);
        if (user == null) return false;

        String otp = String.valueOf(new Random().nextInt(100000, 1000000));

        UserOtp userOtp = new UserOtp();
        userOtp.setOtp(otp);
        userOtp.setUserId(user.getId());
        userOtp.setCreatedTime(LocalDateTime.now());
        userOtpRepo.save(userOtp);

        sendOtpEmail(emailId, user.getName(), otp);
        return true;
    }

    // ─── OTP Verification (returns authenticated User or null) ────
    /**
     * Verifies the OTP. On success:
     *   - marks OTP as used
     *   - updates lastLoginAt on the User
     *   - returns the authenticated User object (for session storage)
     * Returns null on failure.
     */
    public User verifyOtp(String otp) {
        UserOtp userOtp = userOtpRepo.findByOtp(otp);
        if (userOtp == null)      return null;
        if (userOtp.isUsed())     return null;

        LocalDateTime expiryTime = userOtp.getCreatedTime().plusMinutes(1);
        if (LocalDateTime.now().isAfter(expiryTime)) return null;

        // Mark OTP used
        userOtp.setUsed(true);
        userOtpRepo.save(userOtp);

        // Update lastLoginAt
        User user = userRepo.findById(userOtp.getUserId()).orElse(null);
        if (user != null) {
            user.setLastLoginAt(LocalDateTime.now());
            userRepo.save(user);
        }
        return user;
    }

    // ─── Email Sender ─────────────────────────────────────────────
    private void sendOtpEmail(String to, String name, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject("LordAuth — Your One-Time Password");
            helper.setText(buildHtmlEmail(name, otp), true);
            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send OTP email: " + e.getMessage(), e);
        }
    }

    private String buildHtmlEmail(String name, String otp) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <style>
                body { margin:0; padding:0; background:#0a0f1e; font-family:'Segoe UI',Arial,sans-serif; }
                .wrapper { max-width:520px; margin:40px auto; }
                .card { background:linear-gradient(135deg,#111928,#0a0f1e); border:1px solid rgba(255,255,255,0.08); border-radius:16px; overflow:hidden; }
                .header { background:linear-gradient(90deg,#6366f1,#a855f7); padding:32px 40px; text-align:center; }
                .header h1 { color:#fff; margin:0; font-size:24px; font-weight:800; letter-spacing:1px; }
                .header p  { color:rgba(255,255,255,0.8); margin:6px 0 0; font-size:13px; }
                .body { padding:36px 40px; }
                .greeting { color:#cbd5e1; font-size:15px; margin-bottom:24px; }
                .otp-label { color:#94a3b8; font-size:12px; text-transform:uppercase; letter-spacing:2px; margin-bottom:12px; }
                .otp-box { background:rgba(99,102,241,0.12); border:2px solid #6366f1; border-radius:12px; padding:22px; text-align:center; margin-bottom:24px; }
                .otp-code { color:#818cf8; font-size:44px; font-weight:900; letter-spacing:14px; }
                .note { background:rgba(168,85,247,0.1); border-left:3px solid #a855f7; border-radius:4px; padding:12px 16px; color:#c4b5fd; font-size:13px; margin-bottom:24px; }
                .footer { text-align:center; padding:20px 40px; border-top:1px solid rgba(255,255,255,0.06); }
                .footer p { color:#475569; font-size:12px; margin:0; }
                .footer strong { color:#6366f1; }
              </style>
            </head>
            <body>
              <div class="wrapper">
                <div class="card">
                  <div class="header">
                    <h1>🛡️ LordAuth</h1>
                    <p>Anointed Security System</p>
                  </div>
                  <div class="body">
                    <p class="greeting">Greetings, <strong style="color:#e2e8f0">""" + name + """
                    </strong>. Your verified identity awaits.</p>
                    <p class="otp-label">Your One-Time Password</p>
                    <div class="otp-box">
                      <div class="otp-code">""" + otp + """
                      </div>
                    </div>
                    <div class="note">
                      ⚡ This code expires in <strong>60 seconds</strong>. Do not share it with anyone.
                    </div>
                  </div>
                  <div class="footer">
                    <p>Secured by <strong>LordAuth</strong> &mdash; Anointed: Lordradeez</p>
                  </div>
                </div>
              </div>
            </body>
            </html>
            """;
    }
}
