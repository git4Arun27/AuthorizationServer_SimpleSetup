package com.security.oauthserver.repository;

import com.security.oauthserver.entity.Role;
import jakarta.persistence.Entity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

@Entity
public interface RoleRepository extends JpaRepository<Role,Integer> {

    public Optional<Role> findRoleByName(String name);

}
