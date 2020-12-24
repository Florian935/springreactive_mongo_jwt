package com.security.jwt.web.user;

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
public class UserRouter {

    @Bean
    public RouterFunction<ServerResponse> userRoutes(final UserHandler handler) {
        return nest(
                path("/users"),
                route()
                        .POST("", handler::save)
                        .GET("", handler::findAll)
                        .GET("/{username}", handler::findById)
                        .DELETE("", handler::deleteAll)
                        .DELETE("/{username}", handler::deleteById)
                        .build()
        );
    }
}
