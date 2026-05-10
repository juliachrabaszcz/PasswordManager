package com.example.passwordmanager;

import org.springframework.data.repository.CrudRepository;
import java.util.List;

public interface AuditLogRepository extends CrudRepository<AuditLog, Long> {
    List<AuditLog> findAllByOrderByTimestampDesc();
}