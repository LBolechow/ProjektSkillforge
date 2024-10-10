package pl.lukbol.ProjektSkillforge.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.UserRepository;
import pl.lukbol.ProjektSkillforge.Utils.JwtUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class LoginController {


    private JwtUtil jwtUtil;


    private AuthenticationManager authenticationManager;

    private UserRepository userRepository;

    public LoginController(JwtUtil jwtUtil, AuthenticationManager authenticationManager,UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> authenticateUser(@RequestBody User request) {
        String usernameOrEmail = request.getEmail() != null ? request.getEmail() : request.getUsername();

        try {
            String username;
            if (usernameOrEmail.contains("@") && usernameOrEmail.contains(".")) {
                User userByEmail = userRepository.findByEmail(usernameOrEmail);
                if (userByEmail == null) {
                    throw new BadCredentialsException("Błędny email lub hasło.");
                }
                username = userByEmail.getUsername();
            } else {
                username = usernameOrEmail;
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, request.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String token = jwtUtil.generateToken(username);

            Map<String, Object> response = new HashMap<>();
            response.put("token", token);
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "Błędna nazwa użytkownika/email lub hasło."));
        }
    }
}
