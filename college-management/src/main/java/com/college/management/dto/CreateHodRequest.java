package com.college.management.dto;

public class CreateHodRequest {

    private String name;
    private String username;
    private String email;
    private String password;
    private Long departmentId;

    public CreateHodRequest() {}

    public String getName() {
        return name;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public Long getDepartmentId() {
        return departmentId;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setDepartmentId(Long departmentId) {
        this.departmentId = departmentId;
    }
}