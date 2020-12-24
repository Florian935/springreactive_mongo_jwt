package com.security.jwt.service;

import com.security.jwt.domain.User;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author florian935
 */
public interface UserService {

    Mono<User> save(User toSave);
    Flux<User> findAll();
    Mono<User> findByUserName(String userName);
    Mono<Void> deleteAll();
    Mono<Void> deleteById(String userName);
}
