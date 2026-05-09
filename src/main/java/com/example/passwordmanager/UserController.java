package com.example.passwordmanager;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody Map<String, String> body) throws NoSuchAlgorithmException {
        String username = body.get("username");
        String password = body.get("password");

        if (username == null || username.isBlank() || username.length() < 3)
            return ResponseEntity.badRequest().body(Map.of("error", "Login musi mieć min. 3 znaki"));

        if (password == null || password.length() < 8)
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi mieć min. 8 znaków"));

        if (userRepository.existsById(username))
            return ResponseEntity.badRequest().body(Map.of("error", "Użytkownik już istnieje"));

        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(password));
        String salt = java.util.Base64.getEncoder().encodeToString(
                java.security.SecureRandom.getInstanceStrong().generateSeed(32)
        );
        user.setSalt(salt);
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("status", "Konto utworzone"));
    }

    private String odmienMinuty(long minuty) {
        if (minuty == 1) return "1 minutę.";
        if (minuty >= 2 && minuty <= 4) return minuty + " minuty.";
        return minuty + " minut.";
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> body, HttpServletRequest request, HttpServletResponse response) {
        String username = body.get("username");
        String password = body.get("password");

        Optional<User> userOpt = userRepository.findById(username);

        if (userOpt.isEmpty())
            return ResponseEntity.status(401).body(Map.of("error", "Nieprawidłowe dane logowania"));

        User user = userOpt.get();

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(LocalDateTime.now())) {
            long minutesLeft = java.time.Duration.between(LocalDateTime.now(), user.getLockedUntil()).toMinutes() + 1;
            return ResponseEntity.status(403).body(Map.of("error", "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za " + odmienMinuty(minutesLeft)));
        }

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);
            if (attempts >= 3) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(15));
                user.setFailedAttempts(0);
                userRepository.save(user);
                return ResponseEntity.status(403).body(Map.of("error", "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za 15 minut."));
            }
            userRepository.save(user);
            return ResponseEntity.status(401).body(Map.of("error", "Nieprawidłowe dane logowania. Pozostało prób: " + (3 - attempts)));
        }

        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        SecurityContextHolder.getContext().setAuthentication(auth);

        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.saveContext(SecurityContextHolder.getContext(), request, response);

        return ResponseEntity.ok(Map.of("status", "ok", "username", username, "salt", userOpt.get().getSalt()));
    }
}