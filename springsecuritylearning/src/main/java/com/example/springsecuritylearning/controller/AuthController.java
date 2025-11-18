package com.example.springsecuritylearning.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class AuthController {
    @GetMapping("/custom-login")
    public String login(HttpServletRequest request, Model model) {
        CsrfToken token = (CsrfToken) request.getAttribute("_csrf");
        model.addAttribute("token", token);
        
        return "custom-login";  // matches templates/custom-login.html
    }

    @GetMapping("/logout-success")
    public String logoutSuccess(){
        return "logout-success";
    }
}
