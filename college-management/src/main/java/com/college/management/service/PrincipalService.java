package com.college.management.service;

import java.security.Principal;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.college.management.dto.CreateHodRequest;
import com.college.management.dto.CreatePrincipalRequest;
import com.college.management.entity.Department;
import com.college.management.entity.Role;
import com.college.management.entity.User;
import com.college.management.repository.DepartmentRepository;
import com.college.management.repository.RoleRepository;
import com.college.management.repository.UserRepository;
import com.college.management.security.SecurityUtils;


@Service
public class PrincipalService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private DepartmentRepository departmentRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public String createHod(CreateHodRequest request) {

        String role = SecurityUtils.getCurrentUserRole();

        if (!role.equals("PRINCIPAL")) {
            throw new RuntimeException("Only Principal can create HOD");
        }

        Role hodRole = roleRepository.findByRoleName("HOD")
                .orElseThrow(() -> new RuntimeException("Role not found"));

        Department department = departmentRepository
                .findById(request.getDepartmentId())
                .orElseThrow(() -> new RuntimeException("Department not found"));

        User hod = new User();

        hod.setName(request.getName());
        hod.setUsername(request.getUsername());
        hod.setEmail(request.getEmail());
        hod.setPassword(passwordEncoder.encode(request.getPassword()));
        hod.setRole(hodRole);
        hod.setDepartment(department);
        
        Long principalId = SecurityUtils.getCurrentUserId();
        hod.setCreatedBy(principalId);

        userRepository.save(hod);

        return "HOD created successfully";
    }
    
    public String updateHod(Long id, CreateHodRequest request) {

        String role = SecurityUtils.getCurrentUserRole();
        System.out.println("role :-"+role);

        if (!role.equals("PRINCIPAL")) {
            throw new RuntimeException("Only Principal can update HOD");
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getRole().getRoleName().equals("HOD")) {
            throw new RuntimeException("User is not a HOD");
        }

        user.setName(request.getName());
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());

        if (request.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        userRepository.save(user);

        return "Hod updated successfully";
    }
    
    public String deleteHod(Long id) {

        String role = SecurityUtils.getCurrentUserRole();

        if (!role.equals("PRINCIPAL")) {
            throw new RuntimeException("Only {rincipal can delete HOD");
        }

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getRole().getRoleName().equals("HOD")) {
            throw new RuntimeException("User is not a Hod");
        }

        userRepository.delete(user);

        return "HOD deleted successfully";
    }
    
    public List<User> viewHods() {

        String role = SecurityUtils.getCurrentUserRole();

        if (!role.equals("PRINCIPAL")) {
            throw new RuntimeException("Only Principal can view HODs");
        }

        return userRepository.findByRole_RoleName("HOD");
    }
    public List<User> viewStaff() {

        String role = SecurityUtils.getCurrentUserRole();

        if (!role.equals("PRINCIPAL")) {
            throw new RuntimeException("Only Principal can view Staff");
        }

        return userRepository.findByRole_RoleName("STAFF");
    }
    public List<User> viewStudents() {

        String role = SecurityUtils.getCurrentUserRole();

        if (!role.equals("PRINCIPAL")) {
            throw new RuntimeException("Only Principal can view Students");
        }

        return userRepository.findByRole_RoleName("STUDENT");
    }
    
}