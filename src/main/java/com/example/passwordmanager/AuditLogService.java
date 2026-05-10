package com.example.passwordmanager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    public void log(String eventType, String performedBy, String targetUser, String details) {
        auditLogRepository.save(new AuditLog(eventType, performedBy, targetUser, details));
    }
}