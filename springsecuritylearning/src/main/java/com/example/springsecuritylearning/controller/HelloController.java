package com.example.springsecuritylearning.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/")
    public String home(){
        return "Welcome";
    }

    @GetMapping("/admin")
    public String admin() { 
        return "Hello Admin";
    }

    @GetMapping("/user")
    public String user(Authentication auth) { 
        return "User: " + auth.getName() + ", Roles: " + auth.getAuthorities().toString(); 
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/secure-admin")
    public String secureAdmin() {
        return "Admin Method-Level Secured";
    }
}
