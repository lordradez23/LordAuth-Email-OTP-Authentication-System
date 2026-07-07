package com.lordradeez.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.lordradeez.entities.User;
import com.lordradeez.services.UserService;

import jakarta.servlet.http.HttpSession;

@Controller
public class AdminController {

    @Autowired
    private UserService userService;

    @GetMapping("/admin")
    public String adminDashboard(HttpSession session, Model model) {
        User user = (User) session.getAttribute("authUser");
        if (user == null || !"ROLE_ADMIN".equals(user.getRole())) {
            return "redirect:/login";
        }
        
        model.addAttribute("user", user);
        model.addAttribute("usersList", userService.getAllUsers());
        model.addAttribute("auditLogs", userService.getGlobalAuditLogs());
        return "admin-dashboard";
    }

    @org.springframework.web.bind.annotation.PostMapping("/admin/lock")
    public String lockUser(@org.springframework.web.bind.annotation.RequestParam int userId, HttpSession session) {
        User user = (User) session.getAttribute("authUser");
        if (user != null && "ROLE_ADMIN".equals(user.getRole())) {
            userService.setAccountLockStatus(userId, true);
        }
        return "redirect:/admin";
    }

    @org.springframework.web.bind.annotation.PostMapping("/admin/unlock")
    public String unlockUser(@org.springframework.web.bind.annotation.RequestParam int userId, HttpSession session) {
        User user = (User) session.getAttribute("authUser");
        if (user != null && "ROLE_ADMIN".equals(user.getRole())) {
            userService.setAccountLockStatus(userId, false);
        }
        return "redirect:/admin";
    }
}
