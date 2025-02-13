package com.security.oauthserver.repository;

import com.security.oauthserver.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmailId(String emailId);
    boolean existsByEmailId(String emailId);
}

