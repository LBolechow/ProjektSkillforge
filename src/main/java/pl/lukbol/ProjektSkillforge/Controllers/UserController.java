package pl.lukbol.ProjektSkillforge.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import pl.lukbol.ProjektSkillforge.Models.Role;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.RoleRepository;
import pl.lukbol.ProjektSkillforge.Repositories.UserRepository;
import pl.lukbol.ProjektSkillforge.Services.UserService;
import pl.lukbol.ProjektSkillforge.Utils.UserUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Controller
public class UserController {

    private UserRepository userRepository;
    private RoleRepository roleRepository;

    private UserService userService;



    public UserController(UserRepository userRepository, RoleRepository roleRepository, UserService userService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.userService=userService;
    }

    @PostMapping("/user/register")
    public ResponseEntity<Map<String, Object>> registerUser(@RequestBody User request) {
        return userService.registerUser(request);
    }






}
