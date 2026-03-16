package com.college.management.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.college.management.entity.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByRoleName(String roleName);

}