package jsy.project.base.entity;

import jakarta.persistence.*;
import jsy.project.base.entity.support.BaseDateEntity;
import jsy.project.base.entity.support.BaseUserRole;
import lombok.Getter;
import lombok.NoArgsConstructor;

import static jakarta.persistence.EnumType.*;
import static jakarta.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@Table(name = "users")
public class BaseUser extends BaseDateEntity {
    @Id @GeneratedValue(strategy = IDENTITY)
    private Long id;

    private String username;
    private String password;

    @Enumerated(STRING)
    private BaseUserRole role;


    public BaseUser(String username, String password, BaseUserRole role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }
}
