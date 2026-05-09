package com.example.passwordmanager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private static final Logger logger = LoggerFactory.getLogger(VaultController.class);

    @Autowired
    private VaultRepository vaultRepository;

    @GetMapping("/{username}")
    public Vault getVault(@PathVariable String username) {
        checkAccess(username);
        return vaultRepository.findById(username).orElse(new Vault());
    }

    @PostMapping("/{username}")
    public Map<String, String> saveVault(@PathVariable String username, @RequestBody Vault vaultData) {
        checkAccess(username);
        vaultData.setUsername(username);
        vaultRepository.save(vaultData);
        logger.info("Sejf zaktualizowany: {}", username);
        return Map.of("status", "success");
    }

    private void checkAccess(String username) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        if (!username.equals(currentUser)) {
            logger.warn("Nieautoryzowana próba dostępu do sejfu '{}' przez '{}'", username, currentUser);
            throw new RuntimeException("Nieautoryzowany dostęp!");
        }
    }
}