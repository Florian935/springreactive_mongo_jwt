package com.security.jwt.data;

import com.security.jwt.configuration.utils.AuthoritiesConstants;
import com.security.jwt.configuration.utils.Role;
import com.security.jwt.domain.User;
import com.security.jwt.repository.UserRepository;
import com.security.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static com.security.jwt.configuration.utils.AuthoritiesConstants.ROLE_ADMIN;
import static com.security.jwt.configuration.utils.AuthoritiesConstants.ROLE_USER;

/**
 * @author florian935
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @EventListener(ApplicationReadyEvent.class)
    public void init() {
        final String ROLE_ADMIN = "ROLE_ADMIN";
        final String ROLE_USER = "ROLE_USER";
        log.info("Start data initialization ...");

        this.userRepository
                .deleteAll()
                .thenMany(
                        Flux.just("user", "admin")
                                .flatMap(userName -> {
                                    List<String> roles = "user".equals(userName)
                                            ? Collections.singletonList(ROLE_USER)
                                            : Arrays.asList(ROLE_USER, ROLE_ADMIN);

                                    User toSave = buildUser(userName, roles);
                                    return userRepository.save(toSave);
                                }))
                .subscribe(
                        null,
                        null,
                        () -> log.info("Done initialization ...")
                );
    }

    private User buildUser(final String userName, final List<String> roles) {
        return User.builder()
                .id(UUID.randomUUID().toString())
                .userName(userName)
                .password(passwordEncoder.encode("password"))
                .roles(roles)
                .build();
    }
}
