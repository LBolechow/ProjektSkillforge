package pl.lukbol.ProjektSkillforge.Models;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
@Setter
@Getter
@Entity
public class LoginHistory {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String username;
    private Date loginTime;

    public LoginHistory() {
    }

    public LoginHistory(String username, Date loginTime) {
        this.username = username;
        this.loginTime = loginTime;
    }


}
