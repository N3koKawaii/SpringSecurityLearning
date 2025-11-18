package com.example.springsecuritylearning.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/admin")
    public String admin() { 
        return "Hello Admin";
    }

    @GetMapping("/user")
    public String user() { 
        return "Hello User";
    }
}
