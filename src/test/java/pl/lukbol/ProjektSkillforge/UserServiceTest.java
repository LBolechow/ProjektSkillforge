package pl.lukbol.ProjektSkillforge;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.ModelAndView;
import pl.lukbol.ProjektSkillforge.Models.*;
import pl.lukbol.ProjektSkillforge.Repositories.*;
import pl.lukbol.ProjektSkillforge.Services.UserService;
import pl.lukbol.ProjektSkillforge.Utils.JwtUtil;
import pl.lukbol.ProjektSkillforge.Utils.UserUtils;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private Authentication authentication;
    @Mock
    private UserRepository userRepository;

    @Mock
    private UserDetails userDetails;
    @Mock
    private UserUtils userUtils;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private UserService userService;

    @Mock
    private PasswordEncoder passwordEncoder;
     @Mock
    private JwtUtil jwtUtil;
    @Mock
     private AuthenticationManager authenticationManager;

    @Mock
    private LoginHistoryRepository loginHistoryRepository;

    @Mock
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Mock
    private ActivationTokenRepository activationTokenRepository;

    @Mock
    private PasswordTokenRepository passwordTokenRepository;

    @Mock
    private KafkaTemplate<String, String> kafkaTemplate;

    public UserServiceTest() {
    }

    @Test
    public void testAuthenticateUser() {
        String usernameOrEmail = "test@test.com";
        String password = "Password123!";
        String username = "testuser";
        String token = "mockedToken";

        User user = new User("Jan", "Kowalski", usernameOrEmail, "123456789", "encodedPassword", username, true);
        when(userRepository.findByEmail(usernameOrEmail)).thenReturn(user);
        when(userRepository.findOptionalByUsername(username)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any())).thenReturn(mock(Authentication.class));
        when(jwtUtil.generateToken(username)).thenReturn(token);

        ResponseEntity<Map<String, Object>> response = userService.authenticateUser(usernameOrEmail, password);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertEquals(token, body.get("token"));
        assertEquals("http://localhost:8080/main", body.get("redirectUrl"));
        assertEquals(username, body.get("username"));

        verify(userRepository).findByEmail(usernameOrEmail);
        verify(userRepository).findOptionalByUsername(username);
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(userUtils).saveLogin(username);
    }
    @Test
    public void testRegisterUser() {

        when(userUtils.emailExists("test@test.com")).thenReturn(false);
        when(userUtils.phoneNumberExists("123456789")).thenReturn(false);
        when(userUtils.usernameExists("testuser")).thenReturn(false);
        when(userUtils.isValidPassword("Password123!")).thenReturn(true);

        Role role = mock(Role.class);
        when(roleRepository.findByName("ROLE_CLIENT")).thenReturn(role);

        when(passwordEncoder.encode("Password123!")).thenReturn("encodedPassword");

        User user = mock(User.class);
        when(userRepository.save(any(User.class))).thenReturn(user);
        doNothing().when(userUtils).createAccountActivationToken("test@test.com");

        when(userUtils.createSuccessResponse(anyString()))
                .thenAnswer(invocation -> {
                    Map<String, Object> successResponse = new HashMap<>();
                    successResponse.put("success", true);
                    successResponse.put("message", "Poprawnie utworzono konto. Na adres email został wysłany link aktywacyjny.");
                    return ResponseEntity.ok(successResponse);
                });

        ResponseEntity<Map<String, Object>> response = userService.registerUser("testuser", "Jan", "Kowalski", "test@test.com", "123456789", "Password123!");


        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().containsKey("message"));
        assertEquals("Poprawnie utworzono konto. Na adres email został wysłany link aktywacyjny.", response.getBody().get("message"));


        verify(userRepository).save(any(User.class));
        verify(userUtils).createAccountActivationToken("test@test.com");
        verify(userUtils).createSuccessResponse("Poprawnie utworzono konto. Na adres email został wysłany link aktywacyjny.");
    }

    @Test
    public void testGetUserDetails() {

        String username = "testuser";
        User user = mock(User.class);

        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(username);

        when(userRepository.findOptionalByUsername(username)).thenReturn(Optional.of(user));

        ResponseEntity<User> response = userService.getUserDetails(authentication);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(user, response.getBody());


        verify(authentication).getPrincipal();
        verify(userDetails).getUsername();
        verify(userRepository).findOptionalByUsername(username);
    }

    @Test
    public void testChangeProfile() {
        String username = "testuser";
        String name = "Jan";
        String surname = "Kowalski";
        String email = "test@test.com";
        String phoneNumber = "123456789";
        String password = "Password123!";
        String repeatPassword = "Password123!";

        User user = mock(User.class);

        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(username);
        when(userRepository.findOptionalByUsername(username)).thenReturn(Optional.of(user));
        when(userUtils.isNullOrEmpty(anyString())).thenReturn(false);


        when(passwordEncoder.matches(password, user.getPassword())).thenReturn(false);
        when(passwordEncoder.encode(password)).thenReturn("newEncodedPassword");

        when(userRepository.save(any(User.class))).thenReturn(user);


        when(userUtils.createSuccessResponse(anyString()))
                .thenAnswer(invocation -> {
                    Map<String, Object> successResponse = new HashMap<>();
                    successResponse.put("success", true);
                    successResponse.put("message", "Poprawnie zapisano zmiany.");
                    return ResponseEntity.ok(successResponse);
                });

        ResponseEntity<Map<String, Object>> response = userService.changeProfile(authentication, name, surname, email, phoneNumber, password, repeatPassword);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().containsKey("message"));
        assertEquals("Poprawnie zapisano zmiany.", response.getBody().get("message"));

        verify(userRepository).save(user);
        verify(userUtils).createSuccessResponse("Poprawnie zapisano zmiany.");
    }

    @Test
    public void testDeleteUser() {
        String username = "validUsername";
        User user = mock(User.class);

        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(username);
        when(userRepository.findOptionalByUsername(username)).thenReturn(Optional.of(user));

        when(userUtils.createSuccessResponse("Poprawnie usunięto konto."))
                .thenAnswer(invocation -> {
                    Map<String, Object> successResponse = Map.of(
                            "success", true,
                            "message", "Poprawnie usunięto konto."
                    );
                    return ResponseEntity.ok(successResponse);
                });

        ResponseEntity<Map<String, Object>> response = userService.deleteUser(authentication);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertTrue((Boolean) body.get("success"));
        assertEquals("Poprawnie usunięto konto.", body.get("message"));

        verify(userRepository).findOptionalByUsername(username);
        verify(userRepository).delete(user);
        verify(userUtils).createSuccessResponse("Poprawnie usunięto konto.");
    }

    @Test
    public void testResetPasswordEmail()
    {
        String email = "test@test.com";

        User user = mock(User.class);

        when(userRepository.findOptionalByEmail(email)).thenReturn(Optional.of(user));
        doNothing().when(userUtils).createPasswordResetTokenForUser(user);

        when(userUtils.createSuccessResponse("Wysłano link do resetowania hasła na email."))
                .thenAnswer(invocation -> {
                    Map<String, Object> successResponse = Map.of(
                            "success", true,
                            "message", "Wysłano link do resetowania hasła na email."
                    );
                    return ResponseEntity.ok(successResponse);
                });

        ResponseEntity<Map<String, Object>> response = userService.resetPasswordEmail(email);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        Map<String, Object> body = response.getBody();
        assertNotNull(body);
        assertTrue((Boolean) body.get("success"));
        assertEquals("Wysłano link do resetowania hasła na email.", body.get("message"));

        verify(userRepository).findOptionalByEmail(email);
        verify(userUtils).createPasswordResetTokenForUser(user);
    }

    @Test
    public void testShowResetPasswordPage() {
        String token = "validToken";

        PasswordToken passwordToken = mock(PasswordToken.class);
        when(passwordTokenRepository.findOptionalByToken(token)).thenReturn(Optional.of(passwordToken));
        when(passwordToken.isExpired()).thenReturn(false);

        ModelAndView modelAndView = userService.showResetPasswordPage(token);

        assertNotNull(modelAndView);
        assertEquals("reset", modelAndView.getViewName());
        assertEquals(token, modelAndView.getModel().get("token"));
    }

    @Test
    public void testResetPassword() {
        String token = "validToken";
        String newPassword = "newPassword123";
        String repeatPassword = "newPassword123";

        PasswordToken passwordToken = mock(PasswordToken.class);
        User user = mock(User.class);

        when(passwordTokenRepository.findOptionalByToken(token)).thenReturn(Optional.of(passwordToken));
        when(passwordToken.getUser()).thenReturn(user);
        when(passwordToken.isExpired()).thenReturn(false);
        when(user.getUsername()).thenReturn("validUsername");

        when(userRepository.findOptionalByUsername("validUsername")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(newPassword, user.getPassword())).thenReturn(false);
        when(passwordEncoder.encode(newPassword)).thenReturn("newEncodedPassword");

        when(userRepository.save(user)).thenReturn(user);

        when(userUtils.createSuccessResponse(anyString()))
                .thenAnswer(invocation -> {
                    Map<String, Object> successResponse = new HashMap<>();
                    successResponse.put("success", true);
                    successResponse.put("message", "Poprawnie zmieniono hasło.");
                    return ResponseEntity.ok(successResponse);
                });

        ResponseEntity<Map<String, Object>> response = userService.resetPassword(token, newPassword, repeatPassword);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue((Boolean) response.getBody().get("success"));
        assertEquals("Poprawnie zmieniono hasło.", response.getBody().get("message"));
        verify(user).setPassword("newEncodedPassword");
        verify(userRepository).save(user);
    }

    @Test
    public void testActivateAccount() {
        String token = "validToken";
        ActivationToken activationToken = mock(ActivationToken.class);
        User user = mock(User.class);
        when(activationToken.getUser()).thenReturn(user);
        when(user.getUsername()).thenReturn("validUsername");
        when(activationToken.isExpired()).thenReturn(false);

        when(activationTokenRepository.findOptionalByToken(token)).thenReturn(Optional.of(activationToken));
        when(userRepository.findOptionalByUsername("validUsername")).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);

        when(userUtils.createSuccessResponse(anyString()))
                .thenAnswer(invocation -> {
                    Map<String, Object> successResponse = new HashMap<>();
                    successResponse.put("success", true);
                    successResponse.put("message", "Aktywowane konto! Możesz się zalogować");
                    return ResponseEntity.ok(successResponse);
                });

        ResponseEntity<Map<String, Object>> response = userService.activateAccount(token);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue((Boolean) response.getBody().get("success"));
        assertEquals("Aktywowane konto! Możesz się zalogować", response.getBody().get("message"));

        verify(user).setActivated(true);
        verify(userRepository).save(user);
        verify(userUtils).createSuccessResponse("Aktywowane konto! Możesz się zalogować");
    }

    @Test
    public void testLogout() {
        HttpServletRequest request = mock(HttpServletRequest.class);

        String token = "mockedToken";
        when(jwtUtil.extractJwtFromRequest(request)).thenReturn(token);

        Claims claims = mock(Claims.class);
        Date issuedAt = new Date();
        when(jwtUtil.extractAllClaims(token)).thenReturn(claims);
        when(claims.getIssuedAt()).thenReturn(issuedAt);

        BlacklistedToken blacklistedToken = new BlacklistedToken(token, issuedAt);
        when(blacklistedTokenRepository.save(any(BlacklistedToken.class))).thenReturn(blacklistedToken);


        when(userUtils.createSuccessResponse("Wylogowano pomyślnie"))
                .thenReturn(ResponseEntity.ok(Collections.singletonMap("message", "Wylogowano pomyślnie")));


        ResponseEntity<Map<String, Object>> response = userService.logout(request);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Wylogowano pomyślnie", response.getBody().get("message"));


        verify(jwtUtil).extractJwtFromRequest(request);
        verify(jwtUtil).extractAllClaims(token);
        verify(blacklistedTokenRepository).save(any(BlacklistedToken.class));
        verify(userUtils).createSuccessResponse("Wylogowano pomyślnie");
    }

    @Test
    public void testGetLoginHistory()
    {
        String username = "testuser";

        Date testDate = new Date();
        Date testDate2 = new Date(System.currentTimeMillis() - 3600000);
        Date testDate3 = new Date(System.currentTimeMillis() - 10000);

        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(username);

        List<LoginHistory> mockLoginHistories = Arrays.asList(
                new LoginHistory("testuser", testDate),
                new LoginHistory("testuser", testDate2),
                new LoginHistory("testuser", testDate3)
        );

        when(loginHistoryRepository.findAllByUsername("testuser")).thenReturn(mockLoginHistories);

        ResponseEntity<List<LoginHistory>> response = userService.getLoginHistory(authentication);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(3, response.getBody().size());
        assertEquals("testuser", response.getBody().get(0).getUsername());

        verify(loginHistoryRepository).findAllByUsername("testuser");
    }



}
