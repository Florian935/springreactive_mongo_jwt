package com.security.jwt.domain;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.NotEmpty;
import java.util.List;

import static com.security.jwt.configuration.utils.AuthoritiesConstants.ROLE_USER;
import static java.lang.String.format;

/**
 * @author florian935
 */
@Document(collection = "user")
@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Builder
public class User {
    @Id private String id;
    @NonNull @NotEmpty private String userName;
    @NonNull @NotEmpty private String password;
    @Builder.Default() private boolean active = true;
    @Builder.Default() private List<String> roles = List.of(format("ROLE_%s", ROLE_USER));
}
