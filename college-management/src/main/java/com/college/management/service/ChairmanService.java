package com.college.management.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.college.management.dto.CreatePrincipalRequest;
import com.college.management.entity.Role;
import com.college.management.entity.User;
import com.college.management.repository.RoleRepository;
import com.college.management.repository.UserRepository;
import com.college.management.security.SecurityUtils;

@Service
public class ChairmanService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public String createPrincipal(CreatePrincipalRequest request) {
    	
    	 String role = SecurityUtils.getCurrentUserRole();

    	    if (!role.equals("CHAIRMAN")) {
    	        throw new RuntimeException("Only Chairman can create Principal");
    	    }

    	    Role principalRole = roleRepository.findByRoleName("PRINCIPAL")
    	            .orElseThrow(() -> new RuntimeException("Role not found"));


        User principal = new User();

        principal.setName(request.getName());
        principal.setUsername(request.getUsername());
        principal.setEmail(request.getEmail());
        principal.setPassword(passwordEncoder.encode(request.getPassword()));
        principal.setRole(principalRole);
        principal.setDepartment(null);
        
        Long chairmanId = SecurityUtils.getCurrentUserId();
        
        principal.setCreatedBy(chairmanId);

        userRepository.save(principal);

        return "Principal created successfully";
    }
    
    public String updatePrincipal(Long id, CreatePrincipalRequest request) {

        String role = SecurityUtils.getCurrentUserRole();
        System.out.println("role :-"+role);

        if (!role.equals("CHAIRMAN")) {
            throw new RuntimeException("Only Chairman can update Principal");
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getRole().getRoleName().equals("PRINCIPAL")) {
            throw new RuntimeException("User is not a Principal");
        }

        user.setName(request.getName());
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());

        if (request.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        userRepository.save(user);

        return "Principal updated successfully";
    }
    
    public String deletePrincipal(Long id) {

        String role = SecurityUtils.getCurrentUserRole();

        if (!role.equals("CHAIRMAN")) {
            throw new RuntimeException("Only Chairman can delete Principal");
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getRole().getRoleName().equals("PRINCIPAL")) {
            throw new RuntimeException("User is not a Principal");
        }

        userRepository.delete(user);

        return "Principal deleted successfully";
    }
    
    public List<User> viewAllUsers() {

        return userRepository.findAll();
    }
}