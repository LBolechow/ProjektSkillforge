package pl.lukbol.ProjektSkillforge.Models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
@Entity
@Table(name="resetTokens")
public class PasswordToken {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String token;
    @ManyToOne(targetEntity = User.class)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    private Date expiryDate;

    public PasswordToken() {
    }

    public PasswordToken(String token, User user) {
        this.token = token;
        this.user = user;
    }

    public PasswordToken(String token, User user, Date expiryDate) {
        this.token = token;
        this.user = user;
        this.expiryDate = expiryDate;
    }

    public boolean isExpired() {
        return expiryDate.before(new Date());
    }
}
