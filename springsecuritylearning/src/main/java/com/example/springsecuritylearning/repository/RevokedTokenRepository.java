package com.example.springsecuritylearning.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import com.example.springsecuritylearning.model.RevokedToken;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, String>{
    @Modifying
    @Query("DELETE FROM RevokedToken r where r.expiresAt < :now")
    void deleteExpired(long now);

}
