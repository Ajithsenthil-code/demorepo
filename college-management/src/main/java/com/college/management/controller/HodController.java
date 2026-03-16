package com.college.management.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.college.management.entity.User;
import com.college.management.service.HodService;

@RestController
@RequestMapping("/hod")
public class HodController {

    @Autowired
    private HodService hodService;

    @PostMapping("/create-staff")
    public String createStaff(@RequestBody User user) {
        return hodService.createStaff(user);
    }

    @PostMapping("/create-student")
    public String createStudent(@RequestBody User user) {
        return hodService.createStudent(user);
    }
    
    @PutMapping("/update-staff/{staffId}")
    public String updateStaff(@PathVariable Long staffId,
                              @RequestBody User request) {

        return hodService.updateStaff(staffId, request);
    }
    
    @DeleteMapping("/delete-staff/{staffId}")
    public String deleteStaff(@PathVariable Long staffId) {

        return hodService.deleteStaff(staffId);
    }
    
    @PutMapping("/update-student/{studentId}")
    public String updateStudent(@PathVariable Long studentId,
                                @RequestBody User request) {

        return hodService.updateStudent(studentId, request);
    }
    
    @DeleteMapping("/delete-student/{studentId}")
    public String deleteStudent(@PathVariable Long studentId) {

        return hodService.deleteStudent(studentId);
    }

    @GetMapping("/view-staff")
    public List<User> viewStaff() {
        return hodService.viewStaff();
    }

    @GetMapping("/view-students")
    public List<User> viewStudents() {
        return hodService.viewStudents();
    }
}