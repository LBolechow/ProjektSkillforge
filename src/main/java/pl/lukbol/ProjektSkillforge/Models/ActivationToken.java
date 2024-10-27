package pl.lukbol.ProjektSkillforge.Models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
@Entity
@Table(name="activationTokens")
public class ActivationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String token;

    @ManyToOne(targetEntity = User.class)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    private Date expiryDate;

    public ActivationToken() {
    }

    public ActivationToken(String token, User user, Date expiryDate) {
        this.token = token;
        this.user = user;
        this.expiryDate = expiryDate;
    }

    public boolean isExpired() {
        return expiryDate.before(new Date());
    }

}
