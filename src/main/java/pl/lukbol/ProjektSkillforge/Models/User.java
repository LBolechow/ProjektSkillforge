package pl.lukbol.ProjektSkillforge.Models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Entity;
import jakarta.persistence.*;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;


import java.util.Collection;

@Setter
@Getter
@Entity
@Table(name="users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
     private Long Id;

    private String username;

    private String name;

    private String surname;

    private String email;

    private String phoneNumber;

    private String password;

    private boolean activated;



    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(
            name = "users_roles",
            joinColumns = @JoinColumn(
                    name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(
                    name = "role_id", referencedColumnName = "id"))

    @JsonIgnore

    private Collection<Role> roles;

    public User() {
    }

    public User(String name, String surname, String email, String phoneNumber, String password, String username, Boolean activated) {
        this.name = name;
        this.surname = surname;
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.password = password;
        this.username=username;
        this.activated=activated;
    }


}
