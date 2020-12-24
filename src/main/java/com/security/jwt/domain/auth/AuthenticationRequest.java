package com.security.jwt.domain.auth;

import lombok.*;

import java.io.Serializable;

/**
 * @author florian935
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class AuthenticationRequest implements Serializable {

   private static final long serialVersionUID = 456L;
   private String userName;
   private String password;
}
