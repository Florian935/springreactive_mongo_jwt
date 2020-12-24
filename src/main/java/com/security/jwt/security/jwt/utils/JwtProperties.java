package com.security.jwt.security.jwt.utils;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author florian935
 */
@Component
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtProperties {

    private String secretKey = "rzxlszyykpbgqcflzxsqcysyhljt";
    private long validityInMs = 3600000; // 1H
}
