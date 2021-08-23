package com.practice.jwt.controller;

import com.practice.jwt.Util.JWTutil;
import com.practice.jwt.beans.UserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("demo")
@RequiredArgsConstructor
public class JWTdemo {
    private final JWTutil jwtUtil;

    @PostMapping("login")
    private ResponseEntity<?> userLogin(@RequestBody UserDetails userDetails) {
        if (userDetails.getEmail().equals("user@gmail.com") &&
                userDetails.getPassword().equals("userPass") &&
                userDetails.getClientType().equals("user")
        ) {
            return new ResponseEntity<>(jwtUtil.generateToken(userDetails), HttpStatus.ACCEPTED);
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("test")
    private ResponseEntity<?> testMe(@RequestHeader(name = "Authorization") String token, @RequestBody String testMe) {
        if (jwtUtil.validateToken(token)) {

            return ResponseEntity.ok()
                    .headers(getHeaders(token))
                    .body("you message has received: " + testMe);

        }
        return new ResponseEntity<>("Invalid Token", HttpStatus.UNAUTHORIZED);
    }

    private HttpHeaders getHeaders(String token) {
        //create new userDetail and DI
        UserDetails userDetails = new UserDetails();
        userDetails.setEmail(jwtUtil.extractEmail(token));
        userDetails.setClientType((String) jwtUtil.extractAllClaims(token).get("clientType"));
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Authorization", jwtUtil.generateToken(userDetails));
        return httpHeaders;
    }
}
