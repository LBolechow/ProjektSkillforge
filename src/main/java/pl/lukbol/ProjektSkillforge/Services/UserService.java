package pl.lukbol.ProjektSkillforge.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import pl.lukbol.ProjektSkillforge.Models.Role;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.RoleRepository;
import pl.lukbol.ProjektSkillforge.Repositories.UserRepository;
import pl.lukbol.ProjektSkillforge.Utils.JwtUtil;
import pl.lukbol.ProjektSkillforge.Utils.UserUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {
    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtil jwtUtil;

    private UserRepository userRepository;

    private RoleRepository roleRepository;

    @Autowired
    UserUtils userUtils;

    public UserService(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    public ResponseEntity<Map<String, Object>> registerUser(User request) {
        if (userUtils.emailExists(request.getEmail())) {
            return userUtils.createErrorResponse("Użytkownik o takim adresie email już istnieje.");
        }

        if (userUtils.phoneNumberExists(request.getPhoneNumber())) {
            return userUtils.createErrorResponse("Użytkownik o takim numerze telefonu już istnieje.");
        }
        if (userUtils.usernameExists(request.getPhoneNumber())) {
            return userUtils.createErrorResponse("Użytkownik o takiej nazwie użytkownika już istnieje.");
        }

        if (!userUtils.isValidPassword(request.getPassword())) {
            return userUtils.createErrorResponse("Hasło musi spełniać określone kryteria bezpieczeństwa.");
        }


        User regUser = new User(
                request.getUsername(),
                request.getName(),
                request.getSurname(),
                request.getEmail(),
                request.getPhoneNumber(),
                passwordEncoder.encode(request.getPassword())
        );
        //Automatycznie nadaję rolę Client podczas rejestracji.
        Role role = roleRepository.findByName("ROLE_CLIENT");
        regUser.setRoles(Arrays.asList(role));

        try {
            userRepository.save(regUser);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("message", "Wystąpił błąd podczas rejestracji."));
        }

        String token = jwtUtil.generateToken(regUser.getUsername());

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Poprawnie utworzono użytkownika.");
        response.put("token", token);
        return ResponseEntity.ok(response);
    }
}
