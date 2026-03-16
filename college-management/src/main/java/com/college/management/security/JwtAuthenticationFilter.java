package com.college.management.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.JwtException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
    		
    	//Header read 
        String authHeader = request.getHeader("Authorization");

        String token = null;
        String username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {

            token = authHeader.substring(7);
            //Token expired
            //Token modified
            //Wrong secret key
            //Token format Wrong
            try {
            	//username extract
            username = jwtUtil.extractUsername(token);
            
            System.out.println("Username from token: " + username);
            }
            catch(JwtException e) {
            	System.out.println("Invalid JWT Token" + e.getMessage());
            }
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
        		
        	//UserDetails load
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            System.out.println("Authorities: " + userDetails.getAuthorities());
            
            if(jwtUtil.validateToken(token, userDetails.getUsername())) {

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

            authenticationToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );
            	//Authentication set
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }
        }

        filterChain.doFilter(request, response);
    }
}