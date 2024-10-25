package pl.lukbol.ProjektSkillforge;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import pl.lukbol.ProjektSkillforge.Models.*;
import pl.lukbol.ProjektSkillforge.Repositories.*;
import pl.lukbol.ProjektSkillforge.Services.UserService;
import pl.lukbol.ProjektSkillforge.Utils.JwtUtil;
import pl.lukbol.ProjektSkillforge.Utils.UserUtils;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.*;

import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.*;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ProjektSkillforgeApplicationTests {
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private  UserRepository userRepository;
	@Autowired
	private  RoleRepository roleRepository;
	@Autowired
	private  PasswordTokenRepository passwordTokenRepository;
	@Autowired
	private  ActivationTokenRepository activationTokenRepository;
	@Autowired
	private  BlacklistedTokenRepository blacklistedTokenRepository;

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

	@Test
	public void testGetUserDetails() throws Exception {
		String jwtToken = getJwtToken();

		mockMvc.perform(get("/userDetails")
						.header("Authorization", jwtToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.username").value("Admin"));
	}

	private String getJwtToken() throws Exception {
		MvcResult result = mockMvc.perform(post("/login")
						.param("usernameOrEmail", "Admin")
						.param("password", "admin1234"))
				.andExpect(status().isOk())
				.andReturn();

		String responseBody = result.getResponse().getContentAsString();

		ObjectMapper objectMapper = new ObjectMapper();
		Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
		String token = (String) responseMap.get("token");

		return "Bearer " + token;
	}

	@Transactional
	@Test
	public void testChangeProfileSuccess() throws Exception {
		String jwtToken = getJwtToken();

		// Wysłanie żądania z tokenem JWT oraz wymaganymi parametrami
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.put("/user/apply")
						.header("Authorization", jwtToken)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED)
						.param("name", "Janusz")
						.param("surname", "Nowak")
						.param("email", "admin@testowy.com")
						.param("phoneNumber", "123456789")
						.param("password", "newPassword123!")
						.param("repeatPassword", "newPassword123!"))
				.andExpect(status().isOk())
				.andReturn();

		String responseBody = result.getResponse().getContentAsString();
		assertTrue(responseBody.contains("Poprawnie zapisano zmiany."));

		User updatedUser = userRepository.findOptionalByUsername("Admin").orElseThrow();
		assertEquals("Janusz", updatedUser.getName());
		assertEquals("Nowak", updatedUser.getSurname());
		assertEquals("admin@testowy.com", updatedUser.getEmail());
		assertEquals("123456789", updatedUser.getPhoneNumber());
		assertTrue(new BCryptPasswordEncoder().matches("newPassword123!", updatedUser.getPassword()));
	}

	@Transactional
	@Test
	public void testDeleteUserSuccess() throws Exception {

		User user = new User("testuser", "Jan", "Kowalski", "testuser@example.com", "987654321", "password", true);
		Role role = roleRepository.findByName("ROLE_CLIENT");
		user.setRoles(Arrays.asList(role));
		user.setPassword(passwordEncoder.encode("password123"));
		userRepository.save(user);

		String jwtToken = getJwtToken();
		mockMvc.perform(MockMvcRequestBuilders.delete("/user/deleteUser")
						.header("Authorization", jwtToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Poprawnie usunięto konto."))
				.andReturn();


		assertFalse(userRepository.findOptionalByUsername("testuser").isPresent());
	}

	@Transactional
	@Test
	public void testResetPasswordEmail() throws Exception {


		mockMvc.perform(post("/user/resetPasswordEmail")
						.param("email", "admin@testowy.com"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.message").value("Wysłano link do resetowania hasła na email."))
				.andReturn();

		User user = userRepository.findByEmail("admin@testowy.com");

		PasswordToken token = passwordTokenRepository.findByUserId(user.getId())
				.orElseThrow(() -> new AssertionError("Token resetujący nie został utworzony."));
		assertNotNull(token);
		assertTrue(token.getExpiryDate().after(new Date()));
	}
    @Transactional
	@Test
	public void testResetPassword() throws Exception {
		String token = createPasswordResetTokenForUser();
		String jwtToken = getJwtToken();
		String newPassword = "NewPassword123!";
		String repeatPassword = "NewPassword123!";

		mockMvc.perform(post("/user/resetPassword")
						.param("Authorization", jwtToken)
						.param("token", token)
						.param("newPassword", newPassword)
						.param("repeatPassword", repeatPassword)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.message").value("Poprawnie zmieniono hasło."));
	}
	public String createPasswordResetTokenForUser() {
		String token = UUID.randomUUID().toString();
		Date expiryDate = new Date(System.currentTimeMillis() + 3600000); //+ 1 godzina
		PasswordToken myToken = new PasswordToken(token, userRepository.findByEmail("admin@testowy.com"), expiryDate);
		passwordTokenRepository.save(myToken);
		return token;
	}
    @Transactional
	@Test
	public void testActivateAccount_ValidToken_Success() throws Exception {
		String validToken = createAccountActivationToken();

		mockMvc.perform(post("/activate")
						.param("token", validToken)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.message").value("Aktywowane konto! Możesz się zalogować"));
	}
	public String createAccountActivationToken() {
		String token = UUID.randomUUID().toString();
		Date expiryDate = new Date(System.currentTimeMillis() + 24 * 3600000); //+ 24h
		ActivationToken myToken = new ActivationToken(token, userRepository.findByEmail("admin@testowy.com"), expiryDate);
		activationTokenRepository.save(myToken);
		return token;
	}

	@Transactional
	@Test
	public void testLogout() throws Exception {
		String jwtToken = getJwtToken();

		mockMvc.perform(post("/user/logout")
						.header("Authorization",jwtToken)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.message").value("Wylogowano pomyślnie"));


		String plainToken = jwtToken.startsWith("Bearer ") ? jwtToken.substring(7) : jwtToken;

		Optional<BlacklistedToken> blacklistedToken = blacklistedTokenRepository.findOptionalByToken(plainToken);
		assertTrue(blacklistedToken.isPresent());
	}

	@Transactional
	@Test
	public void testGetLoginHistory() throws Exception {

		String jwtToken = getJwtToken();

		mockMvc.perform(get("/user/login-history")
						.header("Authorization",jwtToken)
						.contentType(MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.length()").value(greaterThan(0)));

	}


}
