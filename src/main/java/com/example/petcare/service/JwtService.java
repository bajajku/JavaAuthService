package com.example.petcare.service;

import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;

/**
 * Service class for handling JWT (JSON Web Token) operations including token generation,
 * validation, and claim extraction.
 */
@Service
public class JwtService {
    /**
     * Secret key used for signing JWT tokens, injected from application properties
     */
    @Value("${security.jwt.secret-key}")
    private String secretKey;

    /**
     * Token expiration time in milliseconds, injected from application properties
     */
    @Value("${security.jwt.expiration-time}")
    private Long expirationTime;

    /**
     * Extracts the username from the JWT token
     * @param token JWT token string
     * @return username stored in the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generic method to extract any claim from the token using a claims resolver function
     * @param token JWT token string
     * @param claimsResolver function to extract specific claim
     * @return extracted claim value
     * 
     * What is a claim?
     * A claim is a piece of information about a subject (typically a user) that is encoded in a JWT.
     * Claims are used to convey information about the subject, such as their identity, roles, or other attributes.
     * Common claims include "sub" (subject), "exp" (expiration time), "iat" (issue time), "aud" (audience), and "jti" (JWT ID).
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generates a JWT token for a user without any extra claims
     * @param userDetails user details object containing username and other info
     * @return JWT token string
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a JWT token with additional claims
     * @param extraClaims additional claims to be added to the token
     * @param userDetails user details object containing username and other info
     * @return JWT token string
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, expirationTime);
    }
    
    /**
     * Gets the configured token expiration time
     * @return expiration time in milliseconds
     */
    public long getExpirationTime() {
        return expirationTime;
    }

    /**
     * Builds a JWT token with specified claims and expiration
     * @param extraClaims additional claims to be added to the token
     * @param userDetails user details object containing username and other info
     * @param expiration token expiration time in milliseconds
     * @return JWT token string
     */
    public String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts
            .builder()
            .claims(extraClaims)
            .subject(userDetails.getUsername())
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(getSignInKey())
            .compact();
    }

    /**
     * Validates if a token is valid for given user details
     * @param token JWT token string
     * @param userDetails user details to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUsername(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * Checks if the token has expired
     * @param token JWT token string
     * @return true if token is expired, false otherwise
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extracts the expiration date from the token
     * @param token JWT token string
     * @return expiration date
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extracts all claims from a token
     * @param token JWT token string
     * @return Claims object containing all token claims
     */
    public Claims extractAllClaims(String token) {
        return Jwts
            .parser()
            .verifyWith(getSignInKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    /**
     * Creates a signing key from the base64 encoded secret key
     * @return SecretKey object used for signing tokens
     */
    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

