package com.college.management.controller;

import org.springframework.beans.factory.annotation.Autowired;
import com.college.management.dto.*;
import org.springframework.web.bind.annotation.*;

import com.college.management.dto.LoginRequest;
import com.college.management.dto.LoginResponse;
import com.college.management.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {

        return authService.login(request);
    }
}