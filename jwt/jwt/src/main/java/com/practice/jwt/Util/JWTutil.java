package com.practice.jwt.Util;

import com.practice.jwt.beans.UserDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Component
@NoArgsConstructor
@AllArgsConstructor
@Data
public class JWTutil {
    /**
     * Signature algorithm field - type of encryption
     */
    private String signatureAlgorithm = SignatureAlgorithm.HS256.getJcaName();

    private String encodedSecretKey = "*******************************";
    /**
     * Decoded secret key field - creates our private key
     */
    private Key decodedSecretKey = new SecretKeySpec(Base64.getDecoder().decode(encodedSecretKey), signatureAlgorithm);


    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        //claims.put("password", userDetails.password);
        claims.put("clientType", userDetails.getClientType());
        String myToken = createToken(claims, userDetails.getEmail());
        System.out.println("New token was created : " + myToken );
        return myToken;
    }

    private String createToken(Map<String, Object> claims, String subject) {
        Instant now = Instant.now();
        return Jwts.builder().setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(30, ChronoUnit.MINUTES)))
                .signWith(this.decodedSecretKey)
                .compact();
    }


    public Claims extractAllClaims(String token) throws ExpiredJwtException {
        JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(this.decodedSecretKey).build();
        System.out.println(jwtParser.parseClaimsJws(token).getSignature());
        return jwtParser.parseClaimsJws(token).getBody();
    }

    public String extractEmail(String token) {
        // System.out.println("email:"+extractAllClaims(token).getSubject());
        return extractAllClaims(token).getSubject();
    }

    public String extractPassword (String token){
        // System.out.println("password:"+extractAllClaims(token).getId());
        return extractAllClaims(token).getId();
    }


    public Date extractExpirationDate(String token) {
        return extractAllClaims(token).getExpiration();
    }

    private boolean isTokenExpired(String token) {
        try {
            extractAllClaims(token);
            return false;
        } catch (ExpiredJwtException | SignatureException err) {
            return true;
        }
    }

    public boolean validateToken(String token) {
        //final String username = extractEmail(token);
        return !isTokenExpired(token) ;
    }
}
