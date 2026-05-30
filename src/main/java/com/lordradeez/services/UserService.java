package com.lordradeez.services;

import java.time.LocalDateTime;
import java.util.Random;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.lordradeez.entities.LoginAuditLog;
import com.lordradeez.entities.PasswordResetToken;
import com.lordradeez.entities.User;
import com.lordradeez.entities.UserOtp;
import com.lordradeez.repositories.LoginAuditLogRepository;
import com.lordradeez.repositories.PasswordResetTokenRepository;
import com.lordradeez.repositories.UserOTPRepository;
import com.lordradeez.repositories.UserRepository;

import jakarta.mail.internet.MimeMessage;

@Service
public class UserService {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Value("${lordauth.app.base-url:http://localhost:9091}")
    private String baseUrl;

    @Autowired
    UserRepository userRepo;

    @Autowired
    UserOTPRepository userOtpRepo;

    @Autowired
    PasswordResetTokenRepository resetTokenRepo;

    @Autowired
    LoginAuditLogRepository auditRepo;

    @Autowired
    JavaMailSender mailSender;

    // ─── Registration ─────────────────────────────────────────────
    public void register(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepo.save(user);
    }

    private static final int    MAX_ATTEMPTS    = 5;
    private static final int    LOCKOUT_MINUTES = 15;

    // ─── Login + OTP Generation ─────────────────────────────────────────
    public LoginResult loginAndGenerateOTP(String emailId, String password) {
        User user = userRepo.findByEmailId(emailId);
        if (user == null) {
            auditRepo.save(new LoginAuditLog(emailId, null, LoginAuditLog.Outcome.FAIL));
            return LoginResult.INVALID_CREDENTIALS;
        }

        // ─ Check lockout ───────────────────────────────────────
        if (user.isLocked()) {
            auditRepo.save(new LoginAuditLog(emailId, null, LoginAuditLog.Outcome.LOCKED));
            return LoginResult.ACCOUNT_LOCKED;
        }

        // ─ Wrong password ────────────────────────────────────
        if (!passwordEncoder.matches(password, user.getPassword())) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);

            if (attempts >= MAX_ATTEMPTS) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCKOUT_MINUTES));
                userRepo.save(user);
                sendLockoutAlertEmail(user.getEmailId(), user.getName());
                auditRepo.save(new LoginAuditLog(emailId, null, LoginAuditLog.Outcome.LOCKED));
                return LoginResult.ACCOUNT_LOCKED;
            }

            userRepo.save(user);
            auditRepo.save(new LoginAuditLog(emailId, null, LoginAuditLog.Outcome.FAIL));
            return LoginResult.INVALID_CREDENTIALS;
        }

        // ─ Good credentials ──────────────────────────────────
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepo.save(user);

        String otp = String.valueOf(new Random().nextInt(100000, 1000000));
        UserOtp userOtp = new UserOtp();
        userOtp.setOtp(otp);
        userOtp.setUserId(user.getId());
        userOtp.setCreatedTime(LocalDateTime.now());
        userOtpRepo.save(userOtp);

        sendOtpEmail(user.getEmailId(), user.getName(), otp);
        return LoginResult.OTP_SENT;
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
            auditRepo.save(new LoginAuditLog(user.getEmailId(), null, LoginAuditLog.Outcome.SUCCESS));
        }
        return user;
    }

    // ─── Forgot Password ──────────────────────────────────────────
    /**
     * Generates a UUID reset token, persists it (15-min expiry), and emails a link.
     * Returns false if email not found.
     */
    public boolean initiatePasswordReset(String emailId) {
        User user = userRepo.findByEmailId(emailId);
        if (user == null) return false;

        String token = UUID.randomUUID().toString();
        PasswordResetToken prt = new PasswordResetToken(
                token,
                user.getId(),
                LocalDateTime.now().plusMinutes(15)
        );
        resetTokenRepo.save(prt);

        String resetLink = baseUrl + "/reset-password?token=" + token;
        sendResetEmail(user.getEmailId(), user.getName(), resetLink);
        return true;
    }

    /**
     * Validates the token, BCrypt-hashes the new password, saves it, marks token used.
     * Returns false if token is invalid, expired, or already used.
     */
    public boolean resetPassword(String token, String newPassword) {
        PasswordResetToken prt = resetTokenRepo.findByToken(token);
        if (prt == null || prt.isUsed() || prt.isExpired()) return false;

        User user = userRepo.findById(prt.getUserId()).orElse(null);
        if (user == null) return false;

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);

        prt.setUsed(true);
        resetTokenRepo.save(prt);
        return true;
    }

    private void sendResetEmail(String to, String name, String resetLink) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject("LordAuth — Password Reset Request");
            helper.setText(buildResetEmail(name, resetLink), true);
            mailSender.send(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to send reset email: " + e.getMessage(), e);
        }
    }

    private String buildResetEmail(String name, String resetLink) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <style>
                body { margin:0; padding:0; background:#0a0f1e; font-family:'Segoe UI',Arial,sans-serif; }
                .wrapper { max-width:520px; margin:40px auto; }
                .card { background:linear-gradient(135deg,#111928,#0a0f1e); border:1px solid rgba(255,255,255,0.08); border-radius:16px; overflow:hidden; }
                .header { background:linear-gradient(90deg,#ec4899,#a855f7); padding:32px 40px; text-align:center; }
                .header h1 { color:#fff; margin:0; font-size:24px; font-weight:800; letter-spacing:1px; }
                .header p  { color:rgba(255,255,255,0.8); margin:6px 0 0; font-size:13px; }
                .body { padding:36px 40px; }
                .greeting { color:#cbd5e1; font-size:15px; margin-bottom:20px; }
                .btn-reset { display:block; width:fit-content; margin:20px auto; background:linear-gradient(90deg,#ec4899,#a855f7); color:#fff; text-decoration:none; padding:14px 32px; border-radius:10px; font-weight:700; font-size:15px; }
                .note { background:rgba(239,68,68,0.1); border-left:3px solid #ef4444; border-radius:4px; padding:12px 16px; color:#fca5a5; font-size:13px; margin-top:20px; }
                .footer { text-align:center; padding:20px 40px; border-top:1px solid rgba(255,255,255,0.06); }
                .footer p { color:#475569; font-size:12px; margin:0; }
                .footer strong { color:#6366f1; }
              </style>
            </head>
            <body>
              <div class="wrapper">
                <div class="card">
                  <div class="header">
                    <h1>🔑 Password Reset</h1>
                    <p>LordAuth — Anointed Security System</p>
                  </div>
                  <div class="body">
                    <p class="greeting">Hello, <strong style="color:#e2e8f0">""" + name + """
                    </strong>. We received a request to reset your password.</p>
                    <a href="""" + resetLink + """" class="btn-reset">Reset My Password</a>
                    <div class="note">
                      ⚠️ This link expires in <strong>15 minutes</strong>. If you did not request this, ignore this email — your account is safe.
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

    // ─── Lockout Alert Email ─────────────────────────────────────────
    private void sendLockoutAlertEmail(String to, String name) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject("LordAuth — ⚠️ Security Alert: Account Locked");
            helper.setText(buildLockoutEmail(name), true);
            mailSender.send(message);
        } catch (Exception e) {
            // Log but don’t bubble — lockout still applied
            System.err.println("Lockout alert email failed: " + e.getMessage());
        }
    }

    private String buildLockoutEmail(String name) {
        return """
            <!DOCTYPE html>
            <html>
            <head><meta charset="UTF-8">
            <style>
              body{margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',Arial,sans-serif;}
              .wrapper{max-width:520px;margin:40px auto;}
              .card{background:linear-gradient(135deg,#1a0a0a,#0f0a1e);border:1px solid rgba(239,68,68,0.2);border-radius:16px;overflow:hidden;}
              .header{background:linear-gradient(90deg,#ef4444,#dc2626);padding:28px 36px;text-align:center;}
              .header h1{color:#fff;margin:0;font-size:22px;font-weight:800;}
              .header p{color:rgba(255,255,255,0.85);margin:6px 0 0;font-size:13px;}
              .body{padding:32px 36px;color:#cbd5e1;font-size:14px;}
              .note{background:rgba(239,68,68,0.1);border-left:3px solid #ef4444;border-radius:4px;padding:12px 16px;color:#fca5a5;font-size:13px;margin:20px 0;}
              .footer{text-align:center;padding:16px 36px;border-top:1px solid rgba(255,255,255,0.06);}
              .footer p{color:#475569;font-size:12px;margin:0;}
            </style></head>
            <body><div class="wrapper"><div class="card">
              <div class="header"><h1>⚠️ Account Locked</h1><p>LordAuth Security Alert</p></div>
              <div class="body">
                <p>Hello <strong style="color:#f1f5f9">""" + name + """
                </strong>,</p>
                <p style="margin-top:12px;">Your LordAuth account has been <strong>temporarily locked</strong> after <strong>5 consecutive failed login attempts</strong>.</p>
                <div class="note">
                  🔒 Your account will automatically unlock in <strong>15 minutes</strong>.<br>
                  If this was not you, please reset your password immediately.
                </div>
                <p><a href="/forgot-password" style="color:#818cf8;font-weight:700;">Reset My Password</a></p>
              </div>
              <div class="footer"><p>Secured by <strong style="color:#6366f1;">LordAuth</strong> — Anointed: Lordradeez</p></div>
            </div></div></body></html>
            """;
    }

    // ─── Email Sender (OTP) ─────────────────────────────────────────
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
