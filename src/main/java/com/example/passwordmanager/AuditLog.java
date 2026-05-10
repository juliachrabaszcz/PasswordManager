package com.example.passwordmanager;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String eventType;
    private String performedBy;
    private String targetUser;

    @Column(columnDefinition = "TEXT")
    private String details;

    private LocalDateTime timestamp;

    public AuditLog() {}

    public AuditLog(String eventType, String performedBy, String targetUser, String details) {
        this.eventType = eventType;
        this.performedBy = performedBy;
        this.targetUser = targetUser;
        this.details = details;
        this.timestamp = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public String getEventType() { return eventType; }
    public String getPerformedBy() { return performedBy; }
    public String getTargetUser() { return targetUser; }
    public String getDetails() { return details; }
    public LocalDateTime getTimestamp() { return timestamp; }
}