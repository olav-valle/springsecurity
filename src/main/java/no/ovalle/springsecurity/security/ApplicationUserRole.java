package no.ovalle.springsecurity.security;


import com.google.common.collect.Sets;

import java.util.Set;

import static no.ovalle.springsecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()), // STUDENT has no permissions
    ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)), // ADMIN has all permissions
    ADMINTRAINEE(Sets.newHashSet(COURSE_READ, STUDENT_READ)); // ADMIN has all permissions

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}
