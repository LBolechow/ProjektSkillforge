package pl.lukbol.ProjektSkillforge.Utils;

import jakarta.transaction.Transactional;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestParam;
import pl.lukbol.ProjektSkillforge.Models.PasswordToken;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.PasswordTokenRepository;
import pl.lukbol.ProjektSkillforge.Repositories.UserRepository;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class UserUtils {

    private UserRepository userRepository;

    private JavaMailSender javaMailSender;

    private PasswordTokenRepository passwordToken;

    public UserUtils(UserRepository userRepository, PasswordTokenRepository passwordToken, JavaMailSender javaMailSender) {
        this.userRepository = userRepository;
        this.passwordToken = passwordToken;
        this.javaMailSender = javaMailSender;

    }

    public boolean emailExists(String email) {
        return userRepository.findByEmail(email) != null;
    }

    public boolean phoneNumberExists(String phoneNumber) {
        return userRepository.findByPhoneNumber(phoneNumber) != null;
    }
    public boolean usernameExists(String username) {
        return userRepository.findByUsername(username) != null;
    }

    private static final String PASSWORD_PATTERN =
            "^(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-\\[\\]{};':\"\\\\|,.<>/?]).{8,}$";

    public static boolean isValidPassword(String password) {
        return password != null && password.matches(PASSWORD_PATTERN);
    }

    public ResponseEntity<Map<String, Object>> createErrorResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", false);
        response.put("message", message);
        return ResponseEntity.badRequest().body(response);
    }
    public ResponseEntity<Map<String, Object>> createSuccessResponse(String message) {
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", message);
        return ResponseEntity.ok(response);
    }
    public boolean isNullOrEmpty(String value) {
        return value == null || value.isEmpty();
    }

    public void sendResetEmail(String to, String newPassword) {
        SimpleMailMessage message = new SimpleMailMessage();
        javaMailSender.send(message);
    }
    public void createPasswordResetTokenForUser(User user) {
        String token = UUID.randomUUID().toString();
        Date expiryDate = new Date(System.currentTimeMillis() + 3600000);
        PasswordToken myToken = new PasswordToken(token, user, expiryDate);
        passwordToken.save(myToken);
        sendPasswordResetEmail(user.getEmail(), token);

    }
    public void sendPasswordResetEmail(String email, String token) {
        String resetLink = "http://localhost:8080/reset?token=" + token; // Zmień na prawidłowy link do resetu hasła
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Resetowanie hasła");
        message.setText("Kliknij w link, aby zresetować swoje hasło: " + resetLink);
        javaMailSender.send(message);
    }

}
