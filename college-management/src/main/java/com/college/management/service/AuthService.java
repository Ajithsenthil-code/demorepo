package com.college.management.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.college.management.dto.LoginRequest;
import com.college.management.dto.LoginResponse;
import com.college.management.entity.User;
import com.college.management.repository.UserRepository;
import com.college.management.security.JwtUtil;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public LoginResponse login(LoginRequest request) {

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username"));

        System.out.println("request .getPassword-->"+request.getPassword()+" user.getpassword-->"+user.getPassword());
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }
        
        System.out.println("User :- "+user);
        String token = jwtUtil.generateToken(
                user.getUsername(),
                user.getRole().getRoleName()
        );

        return new LoginResponse(
                token,
                user.getUsername(),
                user.getRole().getRoleName()
        );
    }
}
