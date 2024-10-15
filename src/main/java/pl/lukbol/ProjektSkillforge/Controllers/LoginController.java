package pl.lukbol.ProjektSkillforge.Controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.UserRepository;
import pl.lukbol.ProjektSkillforge.Services.UserService;
import pl.lukbol.ProjektSkillforge.Utils.JwtUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
@Controller
public class LoginController {

    private UserService userService;

    public LoginController(UserService userService) {
        this.userService=userService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> authenticateUser( @RequestParam String usernameOrEmail,
                                                                 @RequestParam String password) {
        return userService.authenticateUser(usernameOrEmail, password);
    }


}
