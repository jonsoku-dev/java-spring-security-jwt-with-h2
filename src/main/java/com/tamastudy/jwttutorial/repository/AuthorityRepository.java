package com.tamastudy.jwttutorial.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tamastudy.jwttutorial.entity.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
