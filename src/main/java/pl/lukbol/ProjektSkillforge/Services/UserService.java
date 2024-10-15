package pl.lukbol.ProjektSkillforge.Services;

import jakarta.transaction.Transactional;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import pl.lukbol.ProjektSkillforge.Models.PasswordToken;
import pl.lukbol.ProjektSkillforge.Models.Role;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.PasswordTokenRepository;
import pl.lukbol.ProjektSkillforge.Repositories.RoleRepository;
import pl.lukbol.ProjektSkillforge.Repositories.UserRepository;
import pl.lukbol.ProjektSkillforge.Utils.JwtUtil;
import pl.lukbol.ProjektSkillforge.Utils.UserUtils;

import javax.swing.text.html.Option;
import java.util.*;

@Service
public class UserService {

    private PasswordEncoder passwordEncoder;
    private JwtUtil jwtUtil;
    private UserUtils userUtils;

    private UserRepository userRepository;

    private RoleRepository roleRepository;

    private PasswordTokenRepository passwordTokenRepository;


    public UserService(PasswordEncoder passwordEncoder, JwtUtil jwtUtil, UserUtils userUtils, UserRepository userRepository, RoleRepository roleRepository, PasswordTokenRepository passwordTokenRepository) {
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.userUtils = userUtils;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordTokenRepository = passwordTokenRepository;
    }

    @Transactional
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
            return userUtils.createErrorResponse("Wystąpił błąd podczas rejestracji.");
        }

        String token = jwtUtil.generateToken(regUser.getUsername());

        return userUtils.createSuccessResponse("Poprawnie utworzono konto.");
    }
    public User getUserDetails(Authentication authentication)
    {
        if (authentication == null) {
            return null;
        }
        Object principal = authentication.getPrincipal();

        String username = ((UserDetails)principal).getUsername();

        User user = userRepository.findOptionalByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));


        return user;
    }
    @Transactional
    public ResponseEntity<Map<String, Object>> changeProfile(Authentication authentication,
                                                             String name,
                                                             String surname,
                                                             String email,
                                                             String phoneNumber,
                                                             String password,
                                                             String repeatPassword) {

        Object principal = authentication.getPrincipal();
        String username = ((UserDetails) principal).getUsername();

        User user = userRepository.findOptionalByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        if (userUtils.isNullOrEmpty(name) || userUtils.isNullOrEmpty(surname) || userUtils.isNullOrEmpty(email) || userUtils.isNullOrEmpty(phoneNumber)) {
            return userUtils.createErrorResponse("Wszystkie wartości muszą być wypełnione.");
        }

        if (userUtils.isNullOrEmpty(password) && !userUtils.isNullOrEmpty(repeatPassword)) {
            return userUtils.createErrorResponse("Hasła są puste.");
        }

        if (!password.equals(repeatPassword)) {
            return userUtils.createErrorResponse("Hasła nie są takie same.");
        }

        if (passwordEncoder.matches(password, user.getPassword())) {
            return userUtils.createErrorResponse("Nowe hasło jest takie samo jak poprzednie.");
        }
        user.setPassword(passwordEncoder.encode(password));

        try {
            user.setName(name);
            user.setSurname(surname);
            user.setPhoneNumber(phoneNumber);
            user.setEmail(email);
            userRepository.save(user);
        } catch (DataAccessException e) {
            return userUtils.createErrorResponse("Coś poszło nie tak przy zapisie do bazy danych.");
        }

        return userUtils.createSuccessResponse("Poprawnie zapisano zmiany.");
    }

    @Transactional
    public ResponseEntity<Map<String, Object>> deleteUser(Authentication authentication)
    {

        Object principal = authentication.getPrincipal();
        String username = ((UserDetails) principal).getUsername();
        User user = userRepository.findOptionalByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Nie znaleziono użytkownika z nazwą: " + username));
        try
        {
            userRepository.delete(user);
        }
        catch (DataAccessException e)
        {
            return userUtils.createErrorResponse("Nie udało się usunąć konta.");
        }

        return userUtils.createSuccessResponse("Poprawnie usunięto konto.");
    }
    @Transactional
    public ResponseEntity<Map<String, Object>> resetPasswordEmail(String email)
    {
        User user = userRepository.findOptionalByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Brak użytkownika z emailem: " + email));

        try {
            userUtils.createPasswordResetTokenForUser(user);
        }
        catch (DataAccessException e)
        {
            return userUtils.createErrorResponse("Operacja resetu hasła nie powiodła się.");
        }

        return userUtils.createSuccessResponse("Poprawnie usunięto konto.");
    }

    public ModelAndView showResetPasswordPage(String token) {

        if (userUtils.isNullOrEmpty(token))
        {
            userUtils.createErrorResponse("Brak tokena w URL");
        }

        Optional<PasswordToken> passwordToken = passwordTokenRepository.findOptionalByToken(token);

        if (passwordToken.isEmpty() || passwordToken.get().isExpired()) {
            return new ModelAndView("error")
                    .addObject("message", "Token jest nieprawidłowy lub wygasł.");
        }

        ModelAndView modelAndView = new ModelAndView("reset");
        modelAndView.addObject("token", token);
        return modelAndView;
    }
    @Transactional
    public ResponseEntity<Map<String, Object>> resetPassword(String token, String password, String repeatPassword) {
        Optional<PasswordToken> passwordToken = passwordTokenRepository.findOptionalByToken(token);

        if (passwordToken.isEmpty() || passwordToken.get().isExpired()) {
            return userUtils.createErrorResponse("Token jest nieprawidłowy lub wygasł.");
        }

        String username = passwordToken.get().getUser().getUsername();
        User user = userRepository.findOptionalByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Nie znaleziono użytkownika: " + username + " powiązanego z tokenem"));


        if (userUtils.isNullOrEmpty(password) || userUtils.isNullOrEmpty(repeatPassword)) {
            return userUtils.createErrorResponse("Hasła są puste.");
        }


        if (!password.equals(repeatPassword)) {
            return userUtils.createErrorResponse("Hasła nie są takie same.");
        }


        if (passwordEncoder.matches(password, user.getPassword())) {
            return userUtils.createErrorResponse("Nowe hasło jest takie samo jak poprzednie.");
        }


        user.setPassword(passwordEncoder.encode(password));

        try {
            userRepository.save(user);
        } catch (DataAccessException e) {
            return userUtils.createErrorResponse("Wystąpił błąd podczas zmiany hasła");
        }

        return userUtils.createSuccessResponse("Poprawnie zmieniono hasło.");
    }


}
