package com.example.passwordmanager;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "vaults")
public class Vault {

    @Id
    private String username;

    @Column(columnDefinition = "TEXT")
    private String encryptedData;

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getEncryptedData() { return encryptedData; }
    public void setEncryptedData(String encryptedData) { this.encryptedData = encryptedData; }
}