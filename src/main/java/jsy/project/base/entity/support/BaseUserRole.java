package jsy.project.base.entity.support;

public enum BaseUserRole {
    ADMIN, USER;

    public static BaseUserRole fromString(String role) {
        for (BaseUserRole r : BaseUserRole.values()) {
            if (r.name().equalsIgnoreCase(role)) {
                return r;
            }
        }
        throw new IllegalArgumentException("Unknown role: " + role);
    }
}
