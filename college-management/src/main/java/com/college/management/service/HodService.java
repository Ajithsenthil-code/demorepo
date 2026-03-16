package com.college.management.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.college.management.entity.Role;
import com.college.management.entity.User;
import com.college.management.repository.RoleRepository;
import com.college.management.repository.UserRepository;
import com.college.management.security.SecurityUtils;

@Service
public class HodService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // GET CURRENT HOD
    private User getCurrentHod() {

        String username = SecurityUtils.getCurrentUsername();

        User hod = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!hod.getRole().getRoleName().equals("HOD"))    { //Role HOD ila na Error
            throw new RuntimeException("Only HOD can access this");
        }

        return hod;
    }

    // CREATE STAFF
    public String createStaff(User request) {

        User hod = getCurrentHod();

        Role staffRole = roleRepository.findByRoleName("TEACHING_STAFF")
                .orElseThrow(() -> new RuntimeException("Role not found"));

        User staff = new User();

        staff.setName(request.getName());
        staff.setUsername(request.getUsername());
        staff.setEmail(request.getEmail());
        
        System.out.println("Password received = " + request.getPassword());
        staff.setPassword(passwordEncoder.encode(request.getPassword()));
        staff.setRole(staffRole);

        // IMPORTANT
        staff.setDepartment(hod.getDepartment());
      //createby yar create panragalo Avuga id varum
        
        Long hodId = SecurityUtils.getCurrentUserId();
        staff.setCreatedBy(hodId);
        userRepository.save(staff);

        return "Staff created successfully";
    }

    // CREATE STUDENT
    public String createStudent(User request) {

        User hod = getCurrentHod();

        Role studentRole = roleRepository.findByRoleName("STUDENT")
                .orElseThrow(() -> new RuntimeException("Role not found"));

        User student = new User();

        student.setName(request.getName());
        student.setUsername(request.getUsername());
        student.setEmail(request.getEmail());
        student.setPassword(passwordEncoder.encode(request.getPassword()));
        student.setRole(studentRole);

        student.setDepartment(hod.getDepartment());
        //createby yar create panragalo Avuga id varum
        student.setCreatedBy(hod.getId());

        userRepository.save(student);

        return "Student created successfully";
    }

    public String updateStaff(Long staffId, User request) {

        User hod = getCurrentHod();

        User staff = userRepository.findById(staffId)
                .orElseThrow(() -> new RuntimeException("Staff not found"));

        if (!staff.getRole().getRoleName().equals("TEACHING_STAFF")) {
            throw new RuntimeException("User is not staff");
        }

        if (!staff.getDepartment().getId().equals(hod.getDepartment().getId())) {
            throw new RuntimeException("Access denied: Cannot update other department staff");
        }

        staff.setName(request.getName());
        staff.setUsername(request.getUsername());
        staff.setEmail(request.getEmail());

        if (request.getPassword() != null && !request.getPassword().isEmpty()) {
            staff.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        userRepository.save(staff);

        return "Staff updated successfully";
    }
    
    public String deleteStaff(Long staffId) {

        User hod = getCurrentHod();

        User staff = userRepository.findById(staffId)
                .orElseThrow(() -> new RuntimeException("Staff not found"));

        if (!staff.getRole().getRoleName().equals("TEACHING_STAFF")) {
            throw new RuntimeException("User is not staff");
        }

        if (!staff.getDepartment().getId().equals(hod.getDepartment().getId())) {
            throw new RuntimeException("Access denied: Cannot delete other department staff");
        }

        userRepository.delete(staff);

        return "Staff deleted successfully";
    }
    
    public String updateStudent(Long studentId, User request) {

        User hod = getCurrentHod();

        User student = userRepository.findById(studentId)
                .orElseThrow(() -> new RuntimeException("Student not found"));

        if (!student.getRole().getRoleName().equals("STUDENT")) {
            throw new RuntimeException("User is not a student");
        }

        if (!student.getDepartment().getId().equals(hod.getDepartment().getId())) {
            throw new RuntimeException("Access denied: Cannot update other department student");
        }

        student.setName(request.getName());
        student.setUsername(request.getUsername());
        student.setEmail(request.getEmail());

        if (request.getPassword() != null && !request.getPassword().isEmpty()) {
            student.setPassword(passwordEncoder.encode(request.getPassword()));
        }

        userRepository.save(student);

        return "Student updated successfully";
    }
    
    public String deleteStudent(Long studentId) {

        User hod = getCurrentHod();

        User student = userRepository.findById(studentId)
                .orElseThrow(() -> new RuntimeException("Student not found"));

        if (!student.getRole().getRoleName().equals("STUDENT")) {
            throw new RuntimeException("User is not a student");
        }

        if (!student.getDepartment().getId().equals(hod.getDepartment().getId())) {
            throw new RuntimeException("Access denied: Cannot delete other department student");
        }

        userRepository.delete(student);

        return "Student deleted successfully";
    }
    
    // VIEW STAFF
    public List<User> viewStaff() {

        User hod = getCurrentHod();

        return userRepository
                .findByRole_RoleNameAndDepartment_Id("TEACHING_STAFF",
                        hod.getDepartment().getId());
    }

    // VIEW STUDENTS
    public List<User> viewStudents() {

        User hod = getCurrentHod();

        return userRepository
                .findByRole_RoleNameAndDepartment_Id("STUDENT",
                        hod.getDepartment().getId());
    }

}