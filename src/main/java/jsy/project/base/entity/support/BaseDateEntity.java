package jsy.project.base.entity.support;

import jakarta.persistence.MappedSuperclass;

import java.time.LocalDateTime;

@MappedSuperclass
public class BaseDateEntity {
    private LocalDateTime createdDatetime;
    private LocalDateTime updatedDatetime;
}
