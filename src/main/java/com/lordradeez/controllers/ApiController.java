package com.lordradeez.controllers;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lordradeez.entities.LoginAuditLog;
import com.lordradeez.entities.User;
import com.lordradeez.repositories.LoginAuditLogRepository;
import com.lordradeez.services.JwtUtil;
import com.lordradeez.services.LoginResult;
import com.lordradeez.services.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * REST API Controller — stateless, JWT-based alternative to the session-based MVC controller.
 * All responses are JSON.
 *
 * POST /api/register    — Create a new account
 * POST /api/login       — Validate credentials and trigger OTP email
 * POST /api/verify-otp  — Submit OTP and receive a signed JWT on success
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private LoginAuditLogRepository auditRepo;

    /**
     * Register a new user.
     * Body: { "name": "...", "phone": 123, "emailId": "...", "password": "..." }
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody User user) {
        try {
            UserService.RegistrationResult result = userService.registerUser(user);
            if (result == UserService.RegistrationResult.EMAIL_ALREADY_EXISTS) {
                return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Email is already registered."));
            }
            return ResponseEntity.ok(Map.of("status", "success", "message", "User registered successfully. Please verify your email."));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("status", "error", "message", "Registration failed: " + e.getMessage()));
        }
    }

    @GetMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam String token) {
        boolean success = userService.verifyEmail(token);
        if (success) {
            return ResponseEntity.ok(Map.of("status", "success", "message", "Email verified successfully."));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("status", "error", "message", "Invalid or expired verification token."));
        }
    }

    /**
     * Trigger login and OTP generation.
     * Body: { "emailId": "...", "password": "..." }
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> creds) {
        String emailId = creds.get("emailId");
        String password = creds.get("password");

        if (emailId == null || password == null) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "emailId and password are required."));
        }

        LoginResult result = userService.loginAndGenerateOTP(emailId, password);
        switch (result) {
            case OTP_SENT:
                return ResponseEntity.ok(Map.of("status", "success", "message", "OTP sent to your email.", "emailId", emailId));
            case ACCOUNT_LOCKED:
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Account locked due to too many failed attempts."));
            case EMAIL_NOT_VERIFIED:
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("status", "error", "message", "Please verify your email before logging in."));
            case INVALID_CREDENTIALS:
            default:
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("status", "error", "message", "Invalid credentials."));
        }
    }

    /**
     * Verify OTP and receive a JWT token.
     * Body: { "otp": "123456" }
     * Response: { "status": "success", "token": "<jwt>" }
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtp(@RequestBody Map<String, Object> body, jakarta.servlet.http.HttpServletRequest request) {
        String otp = body.get("otp") != null ? body.get("otp").toString() : null;
        String emailId = body.get("emailId") != null ? body.get("emailId").toString() : null;
        boolean rememberMe = false;
        if (body.containsKey("rememberMe")) {
            Object rm = body.get("rememberMe");
            if (rm instanceof Boolean) rememberMe = (Boolean) rm;
            else if (rm instanceof String) rememberMe = Boolean.parseBoolean((String) rm);
        }

        if (otp == null || emailId == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "otp and emailId are required."));
        }

        String ipAddress = request.getRemoteAddr();
        com.lordradeez.entities.User verified = userService.verifyOtp(otp, ipAddress);
        if (verified != null) {
            String token = jwtUtil.generateToken(verified.getEmailId(), rememberMe);
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Authentication successful.",
                    "token", token
            ));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "error", "message", "OTP is invalid or has expired."));
        }
    }

    /**
     * Retrieve audit logs for a specific email.
     * GET /api/audit-logs/{email}
     */
    @GetMapping("/audit-logs/{email}")
    public ResponseEntity<List<LoginAuditLog>> getAuditLogs(@PathVariable String email) {
        return ResponseEntity.ok(auditRepo.findByEmailOrderByTimestampDesc(email));
    }

    /**
     * Update user profile.
     * Body: { "name": "...", "phone": "123" }
     */
    @PostMapping("/update-profile")
    public ResponseEntity<Map<String, String>> updateProfile(@org.springframework.web.bind.annotation.RequestHeader(value = "Authorization", required = false) String authHeader,
                                                             @RequestBody Map<String, String> body) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "error", "message", "Missing or invalid token"));
        }
        String token = authHeader.substring(7);
        if (!jwtUtil.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "error", "message", "Invalid or expired token"));
        }
        
        String email = jwtUtil.extractEmail(token);
        User user = userService.getUserByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("status", "error", "message", "User not found"));
        }

        String name = body.get("name");
        String phoneStr = body.get("phone");
        String avatarUrl = body.get("avatarUrl");
        if (name == null || phoneStr == null) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "name and phone are required."));
        }

        try {
            int phone = Integer.parseInt(phoneStr);
            userService.updateProfile(user.getId(), name, phone, avatarUrl);
            return ResponseEntity.ok(Map.of("status", "success", "message", "Profile updated successfully."));
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Phone must be a valid integer."));
        }
    }

    /**
     * Change user password.
     * Body: { "oldPassword": "...", "newPassword": "..." }
     */
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@org.springframework.web.bind.annotation.RequestHeader(value = "Authorization", required = false) String authHeader,
                                                              @RequestBody Map<String, String> body) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "error", "message", "Missing or invalid token"));
        }
        String token = authHeader.substring(7);
        if (!jwtUtil.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "error", "message", "Invalid or expired token"));
        }
        
        String email = jwtUtil.extractEmail(token);
        User user = userService.getUserByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("status", "error", "message", "User not found"));
        }

        String oldPassword = body.get("oldPassword");
        String newPassword = body.get("newPassword");
        if (oldPassword == null || newPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "oldPassword and newPassword are required."));
        }

        boolean success = userService.changePassword(user.getId(), oldPassword, newPassword);
        if (success) {
            return ResponseEntity.ok(Map.of("status", "success", "message", "Password changed successfully."));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "error", "message", "Incorrect old password."));
        }
    }

    /**
     * Delete user account.
     */
    @org.springframework.web.bind.annotation.DeleteMapping("/delete-account")
    public ResponseEntity<Map<String, String>> deleteAccount(@org.springframework.web.bind.annotation.RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "error", "message", "Missing or invalid token"));
        }
        String token = authHeader.substring(7);
        if (!jwtUtil.isTokenValid(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("status", "error", "message", "Invalid or expired token"));
        }
        
        String email = jwtUtil.extractEmail(token);
        User user = userService.getUserByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("status", "error", "message", "User not found"));
        }

        boolean success = userService.deleteAccount(user.getId());
        if (success) {
            return ResponseEntity.ok(Map.of("status", "success", "message", "Account deleted successfully."));
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("status", "error", "message", "Failed to delete account."));
        }
    }
}
