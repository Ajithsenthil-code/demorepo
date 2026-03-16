package com.college.management.controller;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import com.college.management.dto.CreateHodRequest;
import com.college.management.dto.CreatePrincipalRequest;
import com.college.management.entity.User;
import com.college.management.service.PrincipalService;


@RestController
@RequestMapping("/principal")
public class PrincipalController {

    @Autowired
    private PrincipalService principalService;

    @PostMapping("/create-hod")
    public String createHod(@RequestBody CreateHodRequest request) {

        return principalService.createHod(request);
    }
    @PutMapping("/update-hod/{id}")
    public String updateHod(@PathVariable Long id,
                                  @RequestBody CreateHodRequest request) {

        return principalService.updateHod(id, request);
    }
    
    @DeleteMapping("/delete-hod/{id}")
    public String deletePrincipal(@PathVariable Long id) {

        return principalService.deleteHod(id);
    }
    
    @GetMapping("/view-hods")
    public List<User> viewHods() {

        return principalService.viewHods();
    }
    
    @GetMapping("/view-staff")
    public List<User> viewStaff() {

        return principalService.viewStaff();
    }
    
    @GetMapping("/view-students")
    public List<User> viewStudents() {

        return principalService.viewStudents();
    }
}