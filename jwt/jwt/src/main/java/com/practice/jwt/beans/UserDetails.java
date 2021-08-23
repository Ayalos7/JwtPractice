package com.practice.jwt.beans;

import lombok.Data;

@Data
public class UserDetails {
    private String clientType;
    private String email;
    private String password;
}
