package com.example.springsecuritylearning.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping({"/","/home"})
    public String home(Authentication authentication, Model model){

        if(authentication == null || !authentication.isAuthenticated()){
            model.addAttribute("isLogin", "Not Logged In");
        }else{
            model.addAttribute("isLogin", "LOGGED IN as " + authentication.getName());
        }
            
        return "home";
    }
}
