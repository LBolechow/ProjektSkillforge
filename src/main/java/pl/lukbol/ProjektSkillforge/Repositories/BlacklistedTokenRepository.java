package pl.lukbol.ProjektSkillforge.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.lukbol.ProjektSkillforge.Models.BlacklistedToken;

public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {
    BlacklistedToken findByToken(String token);
}
