package com.college.management.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.college.management.entity.Department;

import java.util.Optional;

public interface DepartmentRepository extends JpaRepository<Department, Long> {

    Optional<Department> findByDepartmentName(String departmentName);

}