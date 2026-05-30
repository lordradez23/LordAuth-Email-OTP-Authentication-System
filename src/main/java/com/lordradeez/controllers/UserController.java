package com.lordradeez.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.lordradeez.entities.User;
import com.lordradeez.services.LoginResult;
import com.lordradeez.services.UserService;

import jakarta.servlet.http.HttpSession;

@Controller
public class UserController {

    @Autowired
    UserService userServ;

    // ─── Sign Up ──────────────────────────────────────────────────
    @GetMapping("/")
    public String displaySignUpPage() {
        return "index";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user) {
        userServ.register(user);
        return "login";
    }

    // ─── Login ────────────────────────────────────────────────────
    @GetMapping("/login")
    public String displayLoginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String emailId,
                            @RequestParam String password,
                            HttpSession session) {
        LoginResult result = userServ.loginAndGenerateOTP(emailId, password);
        switch (result) {
            case OTP_SENT -> {
                session.setAttribute("pendingEmail", emailId);
                return "otp";
            }
            case ACCOUNT_LOCKED -> { return "locked"; }
            default            -> { return "loginfail"; }
        }
    }

    // ─── OTP ──────────────────────────────────────────────────────
    @PostMapping("/resendotp")
    public String resendOtp(HttpSession session) {
        String emailId = (String) session.getAttribute("pendingEmail");
        if (emailId != null) {
            userServ.resendOtp(emailId);
        }
        return "otp";
    }

    @PostMapping("/verifyotp")
    public String verifyOTP(@RequestParam String otp,
                            HttpSession session,
                            Model model) {
        User authenticatedUser = userServ.verifyOtp(otp);
        if (authenticatedUser != null) {
            // Store authenticated user in session
            session.removeAttribute("pendingEmail");
            session.setAttribute("authUser", authenticatedUser);
            // Pass user to homepage model
            model.addAttribute("user", authenticatedUser);
            return "homepage";
        }
        return "loginfail";
    }

    // ─── Forgot Password ──────────────────────────────────────────
    @GetMapping("/forgot-password")
    public String showForgotPasswordPage() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam String emailId, Model model) {
        boolean sent = userServ.initiatePasswordReset(emailId);
        // Always show same message to avoid email enumeration
        model.addAttribute("sent", true);
        return "forgot-password";
    }

    @GetMapping("/reset-password")
    public String showResetPasswordPage(@RequestParam String token, Model model) {
        model.addAttribute("token", token);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(@RequestParam String token,
                                       @RequestParam String newPassword,
                                       Model model) {
        boolean success = userServ.resetPassword(token, newPassword);
        if (success) {
            model.addAttribute("success", true);
        } else {
            model.addAttribute("error", true);
            model.addAttribute("token", token);
        }
        return "reset-password";
    }

    // ─── Authenticated Dashboard ──────────────────────────────────
    @GetMapping("/home")
    public String homePage(HttpSession session, Model model) {
        User user = (User) session.getAttribute("authUser");
        if (user == null) return "redirect:/login";
        model.addAttribute("user", user);
        return "homepage";
    }

    // ─── Logout ───────────────────────────────────────────────────
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }
}
