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
    public String registerUser(@ModelAttribute User user, Model model) {
        UserService.RegistrationResult result = userServ.registerUser(user);
        if (result == UserService.RegistrationResult.EMAIL_ALREADY_EXISTS) {
            model.addAttribute("error", "Email already registered!");
            return "index";
        }
        model.addAttribute("msg", "Registration successful! Please check your email to verify your account.");
        return "login";
    }

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam String token, Model model) {
        boolean success = userServ.verifyEmail(token);
        if (success) {
            model.addAttribute("msg", "Email verified successfully! You can now log in.");
        } else {
            model.addAttribute("error", "Invalid or expired verification link.");
        }
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
                            @RequestParam(required = false) String rememberMe,
                            HttpSession session,
                            Model model) {
        LoginResult result = userServ.loginAndGenerateOTP(emailId, password);
        switch (result) {
            case OTP_SENT -> {
                session.setAttribute("pendingEmail", emailId);
                if (rememberMe != null) {
                    session.setAttribute("rememberMe", true);
                }
                return "otp";
            }
            case ACCOUNT_LOCKED -> {
                model.addAttribute("error", "Account locked due to too many failed attempts.");
            }
            case EMAIL_NOT_VERIFIED -> {
                model.addAttribute("error", "Please verify your email before logging in.");
            }
            case INVALID_CREDENTIALS -> {
                model.addAttribute("error", "Invalid credentials.");
            }
        }
        return "loginfail";
    }

    // ─── OTP ──────────────────────────────────────────────────────
    @GetMapping("/otp")
    public String displayOtpPage(HttpSession session) {
        if (session.getAttribute("pendingEmail") == null) return "redirect:/login";
        return "otp";
    }

    @PostMapping("/resendotp")
    public String resendOtp(HttpSession session, Model model) {
        String emailId = (String) session.getAttribute("pendingEmail");
        if (emailId != null) {
            boolean success = userServ.resendOtp(emailId);
            if (!success) {
                model.addAttribute("error", "Please wait 30 seconds before requesting another OTP.");
            } else {
                model.addAttribute("success", "OTP sent successfully.");
            }
        }
        return "otp";
    }

    @PostMapping("/verifyotp")
    public String verifyOTP(@RequestParam String otp,
                            HttpSession session,
                            jakarta.servlet.http.HttpServletRequest request,
                            Model model) {
        String ipAddress = request.getRemoteAddr();
        User authenticatedUser = userServ.verifyOtp(otp, ipAddress);
        if (authenticatedUser != null) {
            // Check remember me
            if (Boolean.TRUE.equals(session.getAttribute("rememberMe"))) {
                session.setMaxInactiveInterval(7 * 24 * 60 * 60); // 7 days
            } else {
                session.setMaxInactiveInterval(30 * 60); // 30 minutes
            }
            
            // Store authenticated user in session
            session.removeAttribute("pendingEmail");
            session.removeAttribute("rememberMe");
            session.setAttribute("authUser", authenticatedUser);
            // Pass user to homepage model
            return renderHomepage(authenticatedUser, model);
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
    private String renderHomepage(User user, Model model) {
        model.addAttribute("user", user);
        model.addAttribute("auditLogs", userServ.getUserAuditLogs(user.getEmailId()));
        return "homepage";
    }

    @GetMapping("/home")
    public String homePage(HttpSession session, Model model) {
        User user = (User) session.getAttribute("authUser");
        if (user == null) return "redirect:/login";
        return renderHomepage(user, model);
    }

    @PostMapping("/update-profile")
    public String updateProfile(@RequestParam String name, 
                                @RequestParam int phone,
                                @RequestParam(required = false) String avatarUrl, 
                                HttpSession session, 
                                Model model) {
        User user = (User) session.getAttribute("authUser");
        if (user == null) return "redirect:/login";

        User updated = userServ.updateProfile(user.getId(), name, phone, avatarUrl);
        if (updated != null) {
            session.setAttribute("authUser", updated);
            model.addAttribute("successMsg", "Profile updated successfully!");
            return renderHomepage(updated, model);
        } else {
            model.addAttribute("errorMsg", "Failed to update profile.");
            return renderHomepage(user, model);
        }
    }

    @PostMapping("/change-password")
    public String changePassword(@RequestParam String oldPassword,
                                 @RequestParam String newPassword,
                                 HttpSession session,
                                 Model model) {
        User user = (User) session.getAttribute("authUser");
        if (user == null) return "redirect:/login";

        boolean success = userServ.changePassword(user.getId(), oldPassword, newPassword);
        if (success) {
            model.addAttribute("successMsg", "Password changed successfully!");
        } else {
            model.addAttribute("errorMsg", "Incorrect old password.");
        }
        return "homepage";
    }

    @PostMapping("/delete-account")
    public String deleteAccount(HttpSession session) {
        User user = (User) session.getAttribute("authUser");
        if (user != null) {
            userServ.deleteAccount(user.getId());
            session.invalidate();
        }
        return "redirect:/login";
    }

    // ─── Logout ───────────────────────────────────────────────────
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }
}
