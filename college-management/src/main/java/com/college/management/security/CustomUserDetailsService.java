package com.college.management.security;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.college.management.entity.User;
import com.college.management.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {
	       
	//user login try  dbla user name eruka details kudu
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new CustomUserDetails(user);
        		
    }
    
//    @Override
//    public UserDetails loadUserByname(String username) throws UsernameNotFoundException {
//    	
//    	User user = userRepository.findByUsername(username)
//    			.orElseThrow(() -> new UsernameNotFoundException("user not found"));
//    	
//    	return new CustomUserDetails(
//    			user.getId(),
//    			user.getUsername(),
//    			user.getPassword(),
//    			Collections.singletonList(
//    					new SimpleGrantedAuthority(user.getRole().getRoleName())
//    					)
//    			);
    }
