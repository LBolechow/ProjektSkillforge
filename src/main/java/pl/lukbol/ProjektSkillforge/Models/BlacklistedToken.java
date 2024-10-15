package pl.lukbol.ProjektSkillforge.Models;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Table(name = "blacklisted_tokens")
public class BlacklistedToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true, nullable = false)
    private String token;

    private Date expiresAt;
    public BlacklistedToken() {}

    public BlacklistedToken(String token, Date expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
    }
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getCreatedAt() {
        return expiresAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.expiresAt = createdAt;
    }

}