package pl.lukbol.ProjektSkillforge.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.lukbol.ProjektSkillforge.Models.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);

    User findByName(String name);

    User findByPhoneNumber(String phoneNumber);

    Optional<User> findOptionalByEmail(String email);

    User findByUsername(String username);

    Optional<User> findOptionalByUsername(String usernameOrEmail);


}
