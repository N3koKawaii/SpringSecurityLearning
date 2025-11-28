package com.example.springsecuritylearning.service;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.example.springsecuritylearning.model.RevokedToken;
import com.example.springsecuritylearning.repository.RevokedTokenRepository;

import jakarta.transaction.Transactional;

@Service
public class JpaTokenRevocationService implements TokenRevocationService {

    private final RevokedTokenRepository repo;

    public JpaTokenRevocationService(RevokedTokenRepository repo) {
        this.repo = repo;
    }

    @Override
    @Transactional
    public void revokeToken(String jti, long millisecondsToLive) {
        if(jti == null) return;
        RevokedToken t = new RevokedToken();
        t.setJti(jti);
        t.setExpiresAt(System.currentTimeMillis() + millisecondsToLive);
        repo.save(t);
    }

    @Override
    public boolean isTokenRevoked(String jti) {
        return repo.existsById(jti);
    }

    @Scheduled(fixedDelay = 60 * 60 * 1000)
    @Transactional
    public void cleanup(){
        repo.deleteExpired(System.currentTimeMillis());
    }

    @Override
    public void revokeAllTokensForUser(String username, long millisecondsToLive) {
        
    }

}
