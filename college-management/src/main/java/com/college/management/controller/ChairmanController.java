package com.college.management.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import com.college.management.dto.CreatePrincipalRequest;
import com.college.management.service.ChairmanService;
import java.util.List;
import com.college.management.entity.User;


@RestController
@RequestMapping("/chairman")
public class ChairmanController {

    @Autowired
    private ChairmanService chairmanService;

    @PostMapping("/create-principal")
    public String createPrincipal(@RequestBody CreatePrincipalRequest request) {

        return chairmanService.createPrincipal(request);
    }
    
    @PutMapping("/update-principal/{id}")
    public String updatePrincipal(@PathVariable Long id,
                                  @RequestBody CreatePrincipalRequest request) {

        return chairmanService.updatePrincipal(id, request);
    }
    
    @DeleteMapping("/delete-principal/{id}")
    public String deletePrincipal(@PathVariable Long id) {

        return chairmanService.deletePrincipal(id);
    }
    
    @GetMapping("/view-users")
    public List<User> viewUsers() {

        return chairmanService.viewAllUsers();
    }
}