package com.security.jwt.configuration;

import com.security.jwt.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.stream.Collectors;

/**
 * @author florian935
 */
@Configuration
public class ReactiveUserDetailsServiceConfig {

    @Bean
    public ReactiveUserDetailsService reactiveUserDetailsService(final UserService userService) {
        return username -> userService
                .findByUserName(username)
                .map(this::buildUser);
    }

    private UserDetails buildUser(com.security.jwt.domain.User user) {
        return User
                .withUsername(user.getUserName())
                .password(user.getPassword())
                .authorities(fromRolesListToGrantedAuthorityList(user.getRoles()))
                .build();
    }

    private List<SimpleGrantedAuthority> fromRolesListToGrantedAuthorityList(List<String> roles) {
        return roles
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
