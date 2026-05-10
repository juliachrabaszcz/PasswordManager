package com.example.passwordmanager;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
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

    @Autowired
    private AuditLogService auditLogService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody Map<String, String> body) throws NoSuchAlgorithmException {
        String username = body.get("username");
        String password = body.get("password");

        if (username == null || username.isBlank() || username.length() < 3)
            return ResponseEntity.badRequest().body(Map.of("error", "Login musi mieć min. 3 znaki"));

        if (password == null || password.length() < 8)
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi mieć min. 8 znaków"));

        if (!password.matches(".*[A-Z].*"))
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi zawierać co najmniej jedną wielką literę"));

        if (!password.matches(".*[0-9].*"))
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi zawierać co najmniej jedną cyfrę"));

        if (!password.matches(".*[^a-zA-Z0-9].*"))
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi zawierać co najmniej jeden znak specjalny"));

        if (userRepository.existsById(username))
            return ResponseEntity.badRequest().body(Map.of("error", "Użytkownik już istnieje"));

        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(password));
        String salt = java.util.Base64.getEncoder().encodeToString(
                java.security.SecureRandom.getInstanceStrong().generateSeed(32)
        );
        user.setSalt(salt);
        user.setRole("USER");
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);

        auditLogService.log("REGISTER", username, username, "Zarejestrowano nowe konto");

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

        if (username == null || username.isBlank() || password == null || password.isBlank())
            return ResponseEntity.status(401).body(Map.of("error", "Nieprawidłowe dane logowania"));

        Optional<User> userOpt = userRepository.findById(username);

        if (userOpt.isEmpty())
            return ResponseEntity.status(401).body(Map.of("error", "Nieprawidłowe dane logowania"));

        User user = userOpt.get();

        if (user.isManuallyLocked())
            return ResponseEntity.status(403).body(Map.of("error", "Twoje konto zostało zablokowane.\nSkontaktuj się z administratorem."));

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
                auditLogService.log("LOGIN_FAILED_LOCKED", username, username, "Konto zablokowane po 3 nieudanych próbach logowania");
                return ResponseEntity.status(403).body(Map.of("error", "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za 15 minut."));
            }
            userRepository.save(user);
            auditLogService.log("LOGIN_FAILED", username, username, "Nieudana próba logowania. Pozostało prób: " + (3 - attempts));
            return ResponseEntity.status(401).body(Map.of("error", "Nieprawidłowe dane logowania. Pozostało prób: " + (3 - attempts)));
        }

        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        auditLogService.log("LOGIN_SUCCESS", username, username, "Udane logowanie");

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        SecurityContextHolder.getContext().setAuthentication(auth);

        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.saveContext(SecurityContextHolder.getContext(), request, response);

        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "username", username,
                "salt", user.getSalt(),
                "role", user.getRole(),
                "createdAt", user.getCreatedAt() != null ? user.getCreatedAt().toString() : "",
                "lastLogin", user.getLastLogin() != null ? user.getLastLogin().toString() : ""
        ));
    }

    @GetMapping("/all")
    public ResponseEntity<?> getAllUsers() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        Optional<User> requester = userRepository.findById(currentUser);
        if (requester.isEmpty() || !"ADMIN".equals(requester.get().getRole()))
            return ResponseEntity.status(403).body(Map.of("error", "Brak dostępu"));

        List<Map<String, Object>> users = new ArrayList<>();
        userRepository.findAll().forEach(u -> {
            Map<String, Object> map = new java.util.LinkedHashMap<>();
            map.put("username", u.getUsername());
            map.put("role", u.getRole());
            map.put("createdAt", u.getCreatedAt() != null ? u.getCreatedAt().toString() : "");
            map.put("lastLogin", u.getLastLogin() != null ? u.getLastLogin().toString() : "");
            map.put("manuallyLocked", u.isManuallyLocked());
            users.add(map);
        });
        return ResponseEntity.ok(users);
    }

    @PostMapping("/{username}/lock")
    public ResponseEntity<?> toggleLock(@PathVariable String username) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        Optional<User> requester = userRepository.findById(currentUser);
        if (requester.isEmpty() || !"ADMIN".equals(requester.get().getRole()))
            return ResponseEntity.status(403).body(Map.of("error", "Brak dostępu"));

        if ("Admin123".equals(username))
            return ResponseEntity.status(403).body(Map.of("error", "Nie można modyfikować konta Admin123"));

        if (username.equals(currentUser))
            return ResponseEntity.badRequest().body(Map.of("error", "Nie możesz zablokować własnego konta"));

        Optional<User> userOpt = userRepository.findById(username);
        if (userOpt.isEmpty()) return ResponseEntity.notFound().build();

        User user = userOpt.get();
        if ("ADMIN".equals(user.getRole()))
            return ResponseEntity.status(403).body(Map.of("error", "Nie można zablokować konta z uprawnieniami administratora."));

        user.setManuallyLocked(!user.isManuallyLocked());
        userRepository.save(user);

        if (user.isManuallyLocked()) {
            auditLogService.log("USER_LOCKED", currentUser, username, "Administrator " + currentUser + " zablokował konto użytkownika " + username);
        } else {
            auditLogService.log("USER_UNLOCKED", currentUser, username, "Administrator " + currentUser + " odblokował konto użytkownika " + username);
        }

        return ResponseEntity.ok(Map.of("manuallyLocked", user.isManuallyLocked()));
    }

    @PostMapping("/{username}/role")
    public ResponseEntity<?> changeRole(@PathVariable String username) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        Optional<User> requester = userRepository.findById(currentUser);
        if (requester.isEmpty() || !"ADMIN".equals(requester.get().getRole()))
            return ResponseEntity.status(403).body(Map.of("error", "Brak dostępu"));

        if ("Admin123".equals(username))
            return ResponseEntity.status(403).body(Map.of("error", "Nie można modyfikować konta Admin123"));

        if (username.equals(currentUser))
            return ResponseEntity.badRequest().body(Map.of("error", "Nie możesz zmienić własnej roli"));

        Optional<User> userOpt = userRepository.findById(username);
        if (userOpt.isEmpty()) return ResponseEntity.notFound().build();

        User user = userOpt.get();
        if (user.isManuallyLocked())
            return ResponseEntity.status(403).body(Map.of("error", "Nie można zmienić uprawnień zablokowanemu użytkownikowi."));

        String oldRole = user.getRole();
        user.setRole("ADMIN".equals(user.getRole()) ? "USER" : "ADMIN");
        userRepository.save(user);

        auditLogService.log("ROLE_CHANGED", currentUser, username, "Administrator " + currentUser + " zmienił rolę użytkownika " + username + " z " + oldRole + " na " + user.getRole());

        return ResponseEntity.ok(Map.of("role", user.getRole()));
    }

    @DeleteMapping("/{username}")
    public ResponseEntity<?> deleteUser(@PathVariable String username) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        Optional<User> requester = userRepository.findById(currentUser);
        if (requester.isEmpty())
            return ResponseEntity.status(403).body(Map.of("error", "Brak dostępu"));

        String requesterRole = requester.get().getRole();
        boolean isSelf = username.equals(currentUser);
        boolean isAdmin = "ADMIN".equals(requesterRole);

        if ("Admin123".equals(username))
            return ResponseEntity.status(403).body(Map.of("error", "Nie można usunąć konta Admin123"));

        if (!isSelf && !isAdmin)
            return ResponseEntity.status(403).body(Map.of("error", "Brak dostępu"));

        Optional<User> userOpt = userRepository.findById(username);
        if (userOpt.isEmpty()) return ResponseEntity.notFound().build();

        User user = userOpt.get();
        if ("ADMIN".equals(user.getRole()) && !isSelf)
            return ResponseEntity.status(403).body(Map.of("error", "Nie można usunąć konta z uprawnieniami administratora"));

        userRepository.delete(user);

        if (isSelf) {
            auditLogService.log("ACCOUNT_DELETED", currentUser, username, "Użytkownik " + currentUser + " usunął własne konto");
        } else {
            auditLogService.log("ACCOUNT_DELETED", currentUser, username, "Administrator " + currentUser + " usunął konto użytkownika " + username);
        }

        return ResponseEntity.ok(Map.of("status", "Usunięto"));
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> body) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        Optional<User> userOpt = userRepository.findById(currentUser);
        if (userOpt.isEmpty())
            return ResponseEntity.status(403).body(Map.of("error", "Brak dostępu"));

        String oldPassword = body.get("oldPassword");
        String newPassword = body.get("newPassword");

        if (oldPassword == null || newPassword == null)
            return ResponseEntity.badRequest().body(Map.of("error", "Brak danych"));

        if (newPassword.length() < 8)
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi mieć min. 8 znaków"));

        if (!newPassword.matches(".*[A-Z].*"))
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi zawierać co najmniej jedną wielką literę"));

        if (!newPassword.matches(".*[0-9].*"))
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi zawierać co najmniej jedną cyfrę"));

        if (!newPassword.matches(".*[^a-zA-Z0-9].*"))
            return ResponseEntity.badRequest().body(Map.of("error", "Hasło musi zawierać co najmniej jeden znak specjalny"));

        User user = userOpt.get();
        if (!passwordEncoder.matches(oldPassword, user.getPasswordHash()))
            return ResponseEntity.status(401).body(Map.of("error", "Nieprawidłowe obecne hasło"));
        if (passwordEncoder.matches(newPassword, user.getPasswordHash()))
            return ResponseEntity.badRequest().body(Map.of("error", "Nowe hasło nie może być takie samo jak obecne"));

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        auditLogService.log("PASSWORD_CHANGED", currentUser, currentUser, "Użytkownik " + currentUser + " zmienił hasło");

        return ResponseEntity.ok(Map.of("status", "Hasło zmienione"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = auth != null ? auth.getName() : null;
        if (currentUser != null) {
            auditLogService.log("LOGOUT", currentUser, currentUser, "Użytkownik " + currentUser + " wylogował się");
        }
        request.getSession().invalidate();
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(Map.of("status", "ok"));
    }

}