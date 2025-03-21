package jsy.project.base.repository;

import jsy.project.base.entity.BaseUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BaseUserRepository extends JpaRepository<BaseUser, Long> {
    Boolean existsByUsername(String username);

    BaseUser findByUsername(String username);
}
