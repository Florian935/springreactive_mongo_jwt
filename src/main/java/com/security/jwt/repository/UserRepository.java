package com.security.jwt.repository;

import com.security.jwt.domain.User;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

/**
 * @author florian935
 */
@Repository
public interface UserRepository extends ReactiveMongoRepository<User, String> {

    Mono<User> findByUserName(String userName);
}
