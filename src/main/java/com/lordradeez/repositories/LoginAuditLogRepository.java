package com.lordradeez.repositories;

import com.lordradeez.entities.LoginAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LoginAuditLogRepository extends JpaRepository<LoginAuditLog, Long> {
    /** Return all audit entries for a given email, newest first. */
    List<LoginAuditLog> findByEmailOrderByTimestampDesc(String email);
}
