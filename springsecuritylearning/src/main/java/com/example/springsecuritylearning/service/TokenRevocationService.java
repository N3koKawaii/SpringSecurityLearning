package com.example.springsecuritylearning.service;

public interface TokenRevocationService {
    void revokeToken(String jti, long millisecondsToLive);
    boolean isTokenRevoked(String jti);
    void revokeAllTokensForUser(String username, long millisecondsToLive); // optional
}
