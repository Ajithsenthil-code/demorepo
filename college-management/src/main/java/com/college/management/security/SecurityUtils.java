package com.college.management.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import com.college.management.security.CustomUserDetails;

public class SecurityUtils {

    public static String getCurrentUserRole() {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        return authentication.getAuthorities()
                .iterator()
                .next()
                .getAuthority();
    }
    
    public static String getCurrentUsername() {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        return authentication.getName();
    }
    
    public static Long getCurrentUserId() {
    	CustomUserDetails user =
    			(CustomUserDetails) SecurityContextHolder
    			.getContext()
    			.getAuthentication()
    			.getPrincipal();
    	
    	return user.getId();
    }
}