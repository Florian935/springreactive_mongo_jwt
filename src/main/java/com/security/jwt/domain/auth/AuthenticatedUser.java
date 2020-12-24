package com.security.jwt.domain.auth;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * @author florian935
 */
//@EqualsAndHashCode(callSuper = true)
//@Data
//@ToString
//@Builder
//public class AuthenticatedUser extends User {
//
//    private boolean active;
//    private String username;
//    private String password;
//    private Collection<? extends GrantedAuthority> authorities;
//
//    public AuthenticatedUser(String username, String password, Collection<? extends GrantedAuthority> authorities, boolean active) {
//        super(username, password, authorities);
//        this.active = active;
//    }
//}
