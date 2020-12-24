package com.security.jwt.web.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

/**
 * @author florian935
 */
@Configuration
public class AuthenticationRouter {

    @Bean
    public RouterFunction<ServerResponse> authRoutes(final AuthenticationHandler handler) {
        return nest(
                path("/auth"),
                route()
                        .POST("", handler::login)
                        .build()
        );
    }
}
