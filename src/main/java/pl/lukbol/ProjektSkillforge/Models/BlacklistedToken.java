package pl.lukbol.ProjektSkillforge.Models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
@Setter
@Getter
@Entity
@Table(name = "blacklisted_tokens")
public class BlacklistedToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column(unique = true, nullable = false)
    private String token;

    private Date expiresAt;
    public BlacklistedToken() {}

    public BlacklistedToken(String token, Date expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
    }


}