package com.security.jwt.configuration;

import com.security.jwt.security.jwt.filter.JwtTokenAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static com.security.jwt.configuration.utils.AuthoritiesConstants.ROLE_ADMIN;
import static com.security.jwt.configuration.utils.AuthoritiesConstants.ROLE_USER;
import static org.springframework.http.HttpMethod.*;

/**
 * @author florian935
 */
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter;

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http,
                                                ReactiveAuthenticationManager reactiveAuthenticationManager) {
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(this::configureAuthorizeExchangeSpec)
                .authenticationManager(reactiveAuthenticationManager)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .requestCache().requestCache(NoOpServerRequestCache.getInstance())
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(SecurityConfig::commence)
                .accessDeniedHandler(SecurityConfig::handle)
                .and()
                .addFilterAt(jwtTokenAuthenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC)
                .build();
    }

    private void configureAuthorizeExchangeSpec(AuthorizeExchangeSpec exchange) {
        final String USERS_URI = "/users/**";
        final String LOGIN_URI = "/login/**";

        exchange
                // login URI
                .pathMatchers(POST, LOGIN_URI).permitAll()

                // users URI
                .pathMatchers(GET, "/users/{username}").access(this::currentUserMatchesPath)
                .pathMatchers(POST, USERS_URI).hasAnyRole(ROLE_USER, ROLE_ADMIN)
                .pathMatchers(DELETE, USERS_URI).hasRole(ROLE_ADMIN)
                .anyExchange().authenticated();
    }

    private static Mono<Void> commence(ServerWebExchange response, AuthenticationException error) {
        return Mono.fromRunnable(() -> response
                .getResponse().setStatusCode(HttpStatus.UNAUTHORIZED));
    }

    private static Mono<Void> handle(ServerWebExchange response, AccessDeniedException error) {
        return Mono.fromRunnable(() -> response
                .getResponse().setStatusCode(HttpStatus.FORBIDDEN));
    }

    private Mono<AuthorizationDecision> currentUserMatchesPath(Mono<Authentication> authentication,
                                                               AuthorizationContext context) {
        return authentication
                .map(a -> context.getVariables().get("username").equals(a.getName()))
                .map(AuthorizationDecision::new);
    }
}
