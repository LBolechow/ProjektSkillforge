package pl.lukbol.ProjektSkillforge.Models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Collection;
@Setter
@Getter
@Entity
@Table(name="privileges")
public class Privilege {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long Id;

    private String name;

    @ManyToMany(mappedBy = "privileges")
    private Collection<Role> roles;

    public Privilege() {
    }

    public Privilege(String name) {
        this.name = name;
    }


}
