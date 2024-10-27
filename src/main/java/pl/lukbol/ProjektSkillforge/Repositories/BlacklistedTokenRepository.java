package pl.lukbol.ProjektSkillforge.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.lukbol.ProjektSkillforge.Models.BlacklistedToken;

import java.util.Optional;

public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {


    Optional<BlacklistedToken> findOptionalByToken(String token);


}
