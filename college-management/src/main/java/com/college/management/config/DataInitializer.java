package com.college.management.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.college.management.entity.Role;
import com.college.management.entity.Department;
import com.college.management.repository.RoleRepository;
import com.college.management.repository.DepartmentRepository;
import com.college.management.entity.User;
import com.college.management.repository.UserRepository;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initRoles(RoleRepository roleRepository) {
        return args -> {
        		//Roles
            String[] roles = {
                    "CHAIRMAN",
                    "PRINCIPAL",
                    "HOD",
                    "TEACHING_STAFF",
                    "NON_TEACHING_STAFF",
                    "STUDENT"
            };

            for (String role : roles) {

                if (roleRepository.findByRoleName(role).isEmpty()) {

                    Role newRole = new Role();
                    newRole.setRoleName(role);
 
                    roleRepository.save(newRole);
                 }
            }
        };
    }

    @Bean
    CommandLineRunner initDepartments(DepartmentRepository departmentRepository) {
        return args -> {
        		//Departments
            String[] departments = {
                    "CSE",
                    "ECE",
                    "EEE",
                    "MECH"
            };

            for (String dept : departments) {

                if (departmentRepository.findByDepartmentName(dept).isEmpty()) {

                    Department department = new Department();
                    department.setDepartmentName(dept);

                    departmentRepository.save(department);
                }
            }
        };
    }
    
    @Bean
    CommandLineRunner initChairman(UserRepository userRepository,
                                   RoleRepository roleRepository,
                                   BCryptPasswordEncoder passwordEncoder) {
        return args -> {
        		//chairman
            String chairmanUsername = "chairman";

            if (userRepository.findByUsername(chairmanUsername).isEmpty()) {

                Role chairmanRole = roleRepository.findByRoleName("CHAIRMAN")
                        .orElseThrow(() -> new RuntimeException("Role not found"));

                User chairman = new User();

                chairman.setName("Chairman");
                chairman.setUsername("chairman");
                chairman.setEmail("chairman@college.com");

                chairman.setPassword(passwordEncoder.encode("chairman@123"));
                

                chairman.setRole(chairmanRole);
                chairman.setDepartment(null);
                chairman.setCreatedBy(null);

                userRepository.save(chairman);
            }
        };
    }
}