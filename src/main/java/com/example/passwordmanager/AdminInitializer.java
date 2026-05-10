package com.example.passwordmanager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

@Component
public class AdminInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${admin.default.password}")
    private String adminDefaultPassword;

    @Override
    public void run(String... args) throws NoSuchAlgorithmException {
        if (!userRepository.existsById("Admin123")) {
            User admin = new User();
            admin.setUsername("Admin123");
            admin.setPasswordHash(passwordEncoder.encode(adminDefaultPassword));
            admin.setRole("ADMIN");
            admin.setCreatedAt(LocalDateTime.now());
            String salt = java.util.Base64.getEncoder().encodeToString(
                    java.security.SecureRandom.getInstanceStrong().generateSeed(32)
            );
            admin.setSalt(salt);
            userRepository.save(admin);
        }
    }
}