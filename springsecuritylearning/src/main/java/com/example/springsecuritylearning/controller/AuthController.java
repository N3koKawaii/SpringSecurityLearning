package com.example.springsecuritylearning.controller;

import java.util.Date;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsecuritylearning.config.JwtUtil;
import com.example.springsecuritylearning.dto.AuthRequest;
import com.example.springsecuritylearning.dto.AuthResponse;
import com.example.springsecuritylearning.dto.RefreshTokenRequest;
import com.example.springsecuritylearning.service.TokenRevocationService;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final TokenRevocationService tokenRevocationService;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest){
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

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> body){
        String token = body.get("token");
        if(!StringUtils.hasText(token)){
            return ResponseEntity.badRequest().body(Map.of("error", "token required"));
        }

        if(token.startsWith("Bearer ")) token = token.substring(7);

        String jti;
        Date exp;

        try {
            jti = jwtUtil.extractJti(token);
            exp = jwtUtil.extractClaim(token, Claims::getExpiration);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid token"));
        }

        long ttl = exp.getTime() - System.currentTimeMillis();
        if(ttl <= 0){
            return ResponseEntity.badRequest().body(Map.of("error", "token already expired"));
        }

        tokenRevocationService.revokeToken(jti, ttl);
        return ResponseEntity.ok(Map.of("message", "token revoked successfully"));
    }
}
