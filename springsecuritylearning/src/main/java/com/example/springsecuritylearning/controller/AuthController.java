package com.example.springsecuritylearning.controller;


import java.util.Map;

import org.apache.catalina.connector.Response;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsecuritylearning.config.JwtUtil;
import com.example.springsecuritylearning.dto.AuthRequest;
import com.example.springsecuritylearning.dto.AuthResponse;
import com.example.springsecuritylearning.dto.RefreshTokenRequest;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest){
        try{
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    authRequest.getUsername(),
                    authRequest.getPassword()
                )
            );

        } catch (BadCredentialsException ex){
            return ResponseEntity.status(401)
                .body(new AuthResponse(null,"Invalid Credentials"));
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());

        String accessToken = jwtUtil.generateToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails, 2592000000L);
        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));

    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request){
        String refreshToken = request.getRefreshToken();

        String username = jwtUtil.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Validate
        if (!jwtUtil.isTokenExpired(refreshToken)){
            String newAccessToken = jwtUtil.generateToken(userDetails);

            return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshToken));
        }

        return ResponseEntity.status(401).body(null);
    }
}
