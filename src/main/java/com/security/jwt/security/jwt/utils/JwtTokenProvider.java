package com.security.jwt.security.jwt.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

import static java.util.stream.Collectors.joining;

/**
 * @author florian935
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JwtTokenProvider {

    private static final String AUTHORITIES_KEY = "roles";
    private final JwtProperties jwtProperties;
    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        String secret = Base64.getEncoder().encodeToString(jwtProperties.getSecretKey().getBytes());
        secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(Authentication authentication) {
//        ReactiveSecurityContextHolder.getContext().map(context -> context.getAuthentication().getAuthorities()).log();
//        ReactiveSecurityContextHolder.getContext().map(context -> context.getAuthentication().getPrincipal()).log();
        String userName = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Claims claims = Jwts.claims().setSubject(userName);
        if (!authorities.isEmpty()) {
            claims.put(
                    AUTHORITIES_KEY,
                    authorities
                            .stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(joining(","))
            );
        }

        Date now = new Date();
        Date validity = new Date(now.getTime() + jwtProperties.getValidityInMs());
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Authentication getAuthenticationFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();

        Object authoritiesClaim = claims.get(AUTHORITIES_KEY);

        Collection<? extends GrantedAuthority> authorities = authoritiesClaim == null
                ? AuthorityUtils.NO_AUTHORITIES
                : AuthorityUtils.commaSeparatedStringToAuthorityList(authoritiesClaim.toString());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean isValidToken(String token) {
        try {
            validateToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            logError(e);
        }
        return false;
    }

    private void validateToken(String token) {
        Jws<Claims> claims = Jwts
                .parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token);
        log.info("expiration date: {}", claims.getBody().getExpiration());
    }

    private void logError(Exception e) {
        log.info("Invalid JWT token: {}", e.getMessage());
        log.trace("Invalid JWT token trace.", e);
    }
}
