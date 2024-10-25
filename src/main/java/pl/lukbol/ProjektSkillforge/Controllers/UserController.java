package pl.lukbol.ProjektSkillforge.Controllers;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Services.UserService;
import pl.lukbol.ProjektSkillforge.Models.LoginHistory;

import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/userDetails")
    public ResponseEntity<User> getUserDetails(Authentication authentication) {
        return userService.getUserDetails(authentication);
    }

    @PostMapping("/user/register")
    public ResponseEntity<Map<String, Object>> registerUser(@RequestParam("username") String username,
                                                            @RequestParam("name") String name,
                                                            @RequestParam("surname") String surname,
                                                            @RequestParam("email") String email,
                                                            @RequestParam("phoneNumber") String phoneNumber,
                                                            @RequestParam("password") String password
                                                            ) {
        return userService.registerUser(username, name, surname, email ,phoneNumber, password);
    }
    @PutMapping("/user/apply")
    public ResponseEntity<Map<String, Object>> changeProfile(Authentication authentication, @RequestParam("name") String name,
                                                             @RequestParam("surname") String surname,
                                                             @RequestParam("email") String email,
                                                             @RequestParam("phoneNumber") String phoneNumber,
                                                             @RequestParam("password") String password,
                                                             @RequestParam("repeatPassword") String repeatPassword)
    {
        return userService.changeProfile(authentication, name, surname, email, phoneNumber, password, repeatPassword);
    }
    @DeleteMapping("/user/deleteUser")
    public ResponseEntity<Map<String, Object>> deleteUser(Authentication authentication) {
        return userService.deleteUser(authentication);
    }
    //Wysyłam tym maila do użytkownika
    @PostMapping("/user/resetPasswordEmail")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestParam String email) {

        return userService.resetPasswordEmail(email);
    }
    //Otwieram widok strony do resetowania hasła
    @GetMapping("/user/resetSite")
    public ModelAndView showResetPasswordPage(@RequestParam String token) {
        return userService.showResetPasswordPage(token);
    }

    //Resetuję hasło w specjalnym widoku
    @PostMapping("/user/resetPassword")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestParam String token, @RequestParam String newPassword, @RequestParam String repeatPassword) {
        return userService.resetPassword(token, newPassword, repeatPassword);
    }
    @PostMapping("/activate")
    public  ResponseEntity<Map<String, Object>> activateAccount(@RequestParam String token){
        return userService.activateAccount(token);
    }

    @PostMapping("/user/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
       return userService.logout(request);
    }
    @GetMapping("/user/login-history")
    public ResponseEntity<List<LoginHistory>> getLoginHistory(Authentication authentication) {

        return userService.getLoginHistory(authentication);
    }
    @GetMapping("/test")
    public ResponseEntity<String> testEndpoint() {
        return ResponseEntity.ok("Test endpoint works!");
    }
}
