package com.example.springsecuritylearning.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Entity
@Data
public class RevokedToken {

    @Id
    private String jti;
    private Long expiresAt;

}
