package pl.lukbol.ProjektSkillforge;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.*;
import pl.lukbol.ProjektSkillforge.Services.UserService;
import pl.lukbol.ProjektSkillforge.Utils.JwtUtil;
import pl.lukbol.ProjektSkillforge.Utils.UserUtils;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ProjektSkillforgeApplicationTests {
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private JwtUtil jwtUtil;
	@Autowired
	private  UserUtils userUtils;
	@Autowired
	private  UserRepository userRepository;
	@Autowired
	private  RoleRepository roleRepository;
	@Autowired
	private  PasswordTokenRepository passwordTokenRepository;
	@Autowired
	private  AuthenticationManager authenticationManager;
	@Autowired
	private  ActivationTokenRepository activationTokenRepository;
	@Autowired
	private  BlacklistedTokenRepository blacklistedTokenRepository;
	@Autowired
	private  LoginHistoryRepository loginHistoryRepository;
	@Autowired
	private  UserService userService;

	@Autowired
	MockMvc mockMvc;



	@Test
	void contextLoads() {
	}

	@Test
	@Transactional
	public void testAuthenticationUser() throws Exception {
		String usernameOrEmail = "admin@testowy.com";
		String password = "admin1234";

		mockMvc.perform(post("/login")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED)
						.param("usernameOrEmail", usernameOrEmail)
						.param("password", password))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.token").exists())
				.andExpect(jsonPath("$.redirectUrl").value("http://localhost:8080/main"))
				.andExpect(jsonPath("$.username").value("Admin"));


	}

	@Transactional
	@Test
	public void testRegisterUserSuccess() throws Exception {
		String username = "testUsername";
		String name = "Jan";
		String surname = "Kowalski";
		String email = "testUsername@test.com";
		String phoneNumber = "987654321";
		String password = "ValidPassword1234!";

		mockMvc.perform(post("/user/register")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED)
						.param("username", username)
						.param("name", name)
						.param("surname", surname)
						.param("email", email)
						.param("phoneNumber", phoneNumber)
						.param("password", password))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Poprawnie utworzono konto. Na adres email został wysłany link aktywacyjny."));

		User registeredUser = userRepository.findOptionalByUsername(username).orElse(null);
		assertNotNull(registeredUser);
		assertEquals(name, registeredUser.getName());
		assertEquals(surname, registeredUser.getSurname());
		assertEquals(email, registeredUser.getEmail());
		assertEquals(phoneNumber, registeredUser.getPhoneNumber());
		assertTrue(passwordEncoder.matches(password, registeredUser.getPassword()));
		assertTrue(registeredUser.getRoles().stream()
				.anyMatch(role -> role.getName().equals("ROLE_CLIENT")));
	}
}
