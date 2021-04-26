package no.ovalle.springsecurity.security;


import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

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

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        // Extract permission description string from each ApplicationUserPermission enum,
        // and create a SimpleGrantedAuthority for it.
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(p -> new SimpleGrantedAuthority(p.getPermission()))
                .collect(Collectors.toSet());

        // Add SimpleGrantedAuthority for "ROLE_NAME" string to set
         permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

         return permissions;
    }
}
