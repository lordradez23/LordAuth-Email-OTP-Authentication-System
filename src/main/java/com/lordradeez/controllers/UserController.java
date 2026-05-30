package com.lordradeez.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.lordradeez.entities.User;
import com.lordradeez.services.UserService;

import jakarta.servlet.http.HttpSession;

@Controller
public class UserController {

    @Autowired
    UserService userServ;

    @GetMapping("/")
    public String displaySignUpPage() {
        return "index";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute User user) {
        userServ.register(user);
        return "login";
    }

    @GetMapping("/login")
    public String displayLoginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String emailId,
                            @RequestParam String password,
                            HttpSession session) {
        boolean status = userServ.loginAndGenerateOTP(emailId, password);
        if (status) {
            // Store email in session so resend knows who to send to
            session.setAttribute("pendingEmail", emailId);
            return "otp";
        } else {
            return "loginfail";
        }
    }

    @PostMapping("/resendotp")
    public String resendOtp(HttpSession session) {
        String emailId = (String) session.getAttribute("pendingEmail");
        if (emailId != null) {
            userServ.resendOtp(emailId);
        }
        return "otp";
    }

    @PostMapping("/verifyotp")
    public String verifyOTP(@RequestParam String otp, HttpSession session) {
        boolean status = userServ.verifyOtp(otp);
        if (status) {
            session.removeAttribute("pendingEmail");
            return "homepage";
        } else {
            return "loginfail";
        }
    }
}
