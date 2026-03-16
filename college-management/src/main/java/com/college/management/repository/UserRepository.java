package com.college.management.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.college.management.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    
    List<User> findByRole_RoleName(String roleName);
    
    List<User> findByRole_RoleNameAndDepartment_Id(String roleName, Long departmentId);

}