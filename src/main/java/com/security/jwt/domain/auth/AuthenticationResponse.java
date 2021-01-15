package com.security.jwt.domain.auth;

import lombok.*;

import java.io.Serializable;
import java.time.Instant;

/**
 * @author florian935
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class AuthenticationResponse implements Serializable {

    private static final long serialVersionUID = 457L;

    private String token;
    private Instant issuedAt;
}
