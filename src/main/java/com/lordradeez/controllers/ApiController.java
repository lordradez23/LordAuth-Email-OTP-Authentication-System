package com.lordradeez.controllers;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.lordradeez.entities.User;
import com.lordradeez.services.JwtUtil;
import com.lordradeez.services.LoginResult;
import com.lordradeez.services.UserService;

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

    /**
     * Register a new user.
     * Body: { "name": "...", "phone": 123, "emailId": "...", "password": "..." }
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody User user) {
        try {
            userService.register(user);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of(
                            "status", "success",
                            "message", "Account created. Please log in to receive your OTP."
                    ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("status", "error", "message", "Registration failed: " + e.getMessage()));
        }
    }

    /**
     * Login and trigger OTP.
     * Body: { "emailId": "...", "password": "..." }
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> body) {
        String emailId = body.get("emailId");
        String password = body.get("password");

        if (emailId == null || password == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "emailId and password are required."));
        }

        LoginResult result = userService.loginAndGenerateOTP(emailId, password);
        return switch (result) {
            case OTP_SENT        -> ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "OTP sent to your registered email. Valid for 60 seconds."
            ));
            case ACCOUNT_LOCKED  -> ResponseEntity.status(423)
                    .body(Map.of("status", "error", "message", "Account locked. Too many failed attempts. Try again in 15 minutes."));
            default              -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("status", "error", "message", "Invalid email or password."));
        };
    }

    /**
     * Verify OTP and receive a JWT token.
     * Body: { "otp": "123456" }
     * Response: { "status": "success", "token": "<jwt>" }
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtp(@RequestBody Map<String, String> body) {
        String otp = body.get("otp");
        String emailId = body.get("emailId");

        if (otp == null || emailId == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "otp and emailId are required."));
        }

        com.lordradeez.entities.User verified = userService.verifyOtp(otp);
        if (verified != null) {
            String token = jwtUtil.generateToken(verified.getEmailId());
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
}
