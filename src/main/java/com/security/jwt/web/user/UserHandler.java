package com.security.jwt.web.user;

import com.security.jwt.domain.ResponseExceptionBody;
import com.security.jwt.domain.User;
import com.security.jwt.dto.UserDto;
import com.security.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.web.reactive.function.server.ServerResponse.*;

/**
 * @author florian935
 */
@Component
@RequiredArgsConstructor
public class UserHandler {

    private final UserService userService;

    public Mono<ServerResponse> save(final ServerRequest request) {
        final Mono<User> user = request
                .bodyToMono(User.class)
                .flatMap(userService::save);

        return status(CREATED).body(user, User.class);
    }

    public Mono<ServerResponse> findAll(final ServerRequest request) {
        return ok()
                .contentType(APPLICATION_JSON)
                .body(userService.findAll().map(UserDto::new), UserDto.class);
    }

    public Mono<ServerResponse> findById(final ServerRequest request) {
        String username = request.pathVariable("username");

        return userService.findByUserName(username)
                .flatMap(user -> ok().bodyValue(new UserDto(user)))
                .switchIfEmpty(status(NOT_FOUND)
                        .bodyValue(new ResponseExceptionBody(String.format(
                                "User with username \"%s\" not found",
                                username)
                                )
                        )
                );
    }

    public Mono<ServerResponse> deleteAll(final ServerRequest request) {
        return userService.deleteAll()
                .then(noContent().build());
    }

    public Mono<ServerResponse> deleteById(final ServerRequest request) {
        String username = request.pathVariable("username");

        return userService.findByUserName(username)
                .flatMap(user -> userService.deleteById(user.getId())
                        .then(noContent().build()))
                .switchIfEmpty(status(NOT_FOUND)
                        .bodyValue(new ResponseExceptionBody(String.format(
                                "User with username \"%s\" not found",
                                username)
                                )
                        )
                );
    }
}
