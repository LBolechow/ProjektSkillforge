package pl.lukbol.ProjektSkillforge.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.lukbol.ProjektSkillforge.Models.PasswordToken;

import java.util.Optional;

public interface PasswordTokenRepository extends JpaRepository<PasswordToken, Long> {

    Optional<PasswordToken> findOptionalByToken(String token);


    void deleteByUserId(Long userId);

    Optional<PasswordToken> findByUserId(Long id);
}
