package com.security.jwt.web.auth;

import com.security.jwt.domain.auth.AuthenticationRequest;
import com.security.jwt.domain.auth.AuthenticationResponse;
import com.security.jwt.security.jwt.utils.JwtTokenProvider;
import com.security.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

import static org.springframework.web.reactive.function.server.ServerResponse.badRequest;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;

/**
 * @author florian935
 */
@Component
@RequiredArgsConstructor
public class AuthenticationHandler {

    private final JwtTokenProvider tokenProvider;
    private final ReactiveAuthenticationManager reactiveAuthenticationManager;

    public Mono<ServerResponse> login(final ServerRequest request) {
        return ok()
                .body(
                        request
                                .bodyToMono(AuthenticationRequest.class)
                                .flatMap(authReq -> reactiveAuthenticationManager
                                        .authenticate(new UsernamePasswordAuthenticationToken(
                                                authReq.getUserName(), authReq.getPassword()
                                        ))
                                .map(tokenProvider::createToken))
                        .map(token -> new AuthenticationResponse(token, Instant.now())),
                        AuthenticationResponse.class)
                .switchIfEmpty(badRequest().build());
    }
}
