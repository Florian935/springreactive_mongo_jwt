package com.security.jwt.dto;

import com.security.jwt.domain.User;
import lombok.*;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class UserDto implements Serializable {

    private static final long serialVersionUID = 459L;
    private String id;
    private String userName;

    public UserDto(User user) {
        this.id = user.getId();
        this.userName = user.getUserName();
    }
}
