package com.example.springsecuritylearning.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.springsecuritylearning.model.AppUser;

public interface UserRepository extends JpaRepository<AppUser, Long>{
    Optional<AppUser> findByUsername(String username);
}
