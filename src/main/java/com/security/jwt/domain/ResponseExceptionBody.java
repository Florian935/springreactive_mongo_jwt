package com.security.jwt.domain;

import lombok.*;

import java.io.Serializable;

/**
 * @author florian935
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@ToString
public class ResponseExceptionBody implements Serializable {

    private static final long serialVersionUID = 782L;
    private String message;
}
