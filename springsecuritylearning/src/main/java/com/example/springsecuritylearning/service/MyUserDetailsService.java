package com.example.springsecuritylearning.service;

import java.util.Map;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.springsecuritylearning.model.MyUser;

@Service
public class MyUserDetailsService implements UserDetailsService{

    private Map<String, MyUser> users = Map.of(
        "user", new MyUser("user", "$2a$10$LnOXf.uw8lYcPLO6fvIGZ.FvFGEfT4XWur0NcGNb9L6jrcagA./Qu", "USER"),
        "admin", new MyUser("admin", "$2a$11$LiWt9beKwG7UL5fbcfYZmudpCkxHO6Olqixf/sRkTvCgJrjUjAvtS", "ADMIN")
    );

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!users.containsKey(username)) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        return users.get(username);
    }

}
