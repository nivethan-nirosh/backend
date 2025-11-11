package com.sketchflow.sketchflow_backend.Model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Document(collection = "users") // This maps the class to a MongoDB collection named "users"
public class User implements UserDetails {

    @Id
    private String id;

    @Indexed(unique = true) // Ensures no two users have the same username
    private String username;

    private String password; // This will be stored HASHED

    // Other profile info you might want
    private String firstName;
    private String lastName;
    private String email;

    // --- UserDetails Methods (required by Spring Security) ---
    // We are keeping this simple. We don't have complex roles.

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // You could return a list of roles (e.g., new SimpleGrantedAuthority("ROLE_USER"))
        return List.of();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}