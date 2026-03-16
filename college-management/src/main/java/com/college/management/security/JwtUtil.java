package com.college.management.security;

import java.util.Date;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {

    private final SecretKey SECRET_KEY = Keys.hmacShaKeyFor("mysecretkeymysecretkeymysecretkey".getBytes());
    
//    private Key key =Keys.hmacShaKeyFor("mysecretkeymysecretkeymysecretkey".getBytes()
//    		);

    private final long EXPIRATION_TIME = 86400000; // 1 day

    public String generateToken(String username, String role) {

        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY)
                .compact();
    }

    public String extractUsername(String token) {

        return getClaims(token).getSubject();
    }

    public String extractRole(String token) {

        return getClaims(token).get("role", String.class);
    }
    //username match aagutha
    public boolean validateToken(String token, String username) {
    	return extractUsername(token).equals(username) && !isTokenExpired(token);
    													//authentication nadaku only if token valis										
    }
    
    public boolean isTokenExpired(String token) {
    	return getClaims(token).getExpiration().before(new Date());
    }
    private Claims getClaims(String token) {

        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}