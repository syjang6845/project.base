package jsy.project.base.dto.request;

import jsy.project.base.entity.support.BaseUserRole;
import lombok.Data;


@Data
public class BaseUserDto {
    private String username;
    private String password;
    private BaseUserRole type;
}
