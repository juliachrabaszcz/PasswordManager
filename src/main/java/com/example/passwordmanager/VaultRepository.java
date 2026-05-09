package com.example.passwordmanager;

import org.springframework.data.repository.CrudRepository;

public interface VaultRepository extends CrudRepository<Vault, String> {
}