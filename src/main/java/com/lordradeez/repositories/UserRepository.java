package com.lordradeez.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.lordradeez.entities.User;

public interface UserRepository extends JpaRepository<User, Integer>{
	User findByEmailId(String emailId);
}
