package com.security.jwt.service;

import com.security.jwt.domain.User;
import com.security.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * @author florian935
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Mono<User> save(User toSave) {
        final User userToSave = buildUser(toSave);

        return userRepository.save(userToSave);
    }

    private User buildUser(User toBuild) {
        return User.builder()
                .id(UUID.randomUUID().toString())
                .userName(toBuild.getUserName())
                .password(passwordEncoder.encode(toBuild.getPassword()))
                .roles(toBuild.getRoles())
                .build();
    }

    @Override
    public Flux<User> findAll() {
        return userRepository.findAll();
    }

    @Override
    public Mono<User> findByUserName(String userName) {
        return userRepository.findByUserName(userName);
    }

    @Override
    public Mono<Void> deleteAll() {
        return userRepository.deleteAll();
    }

    @Override
    public Mono<Void> deleteById(String userName) {
        return userRepository.deleteById(userName);
    }


}
