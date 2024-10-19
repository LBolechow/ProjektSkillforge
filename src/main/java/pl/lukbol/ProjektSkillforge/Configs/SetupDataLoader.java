package pl.lukbol.ProjektSkillforge.Configs;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import pl.lukbol.ProjektSkillforge.Models.Privilege;
import pl.lukbol.ProjektSkillforge.Models.Role;
import pl.lukbol.ProjektSkillforge.Models.User;
import pl.lukbol.ProjektSkillforge.Repositories.PrivilegeRepository;
import pl.lukbol.ProjektSkillforge.Repositories.RoleRepository;
import pl.lukbol.ProjektSkillforge.Repositories.UserRepository;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@Component
@RequiredArgsConstructor
public class SetupDataLoader implements
        ApplicationListener<ContextRefreshedEvent> {
    boolean alreadySetup = false;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    private final RoleRepository roleRepository;
    private final PrivilegeRepository privilegeRepository;

    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent event) {

        //Privileges są dodane, jeżeli by wystąpiła potrzeba wyszczególnienia uprawnień. Na razie w systemie wykorzystywane są tylko Role.
        if (alreadySetup)
            return;
        Privilege readPrivilege
                = createPrivilegeIfNotFound("READ_PRIVILEGE");
        Privilege writePrivilege
                = createPrivilegeIfNotFound("WRITE_PRIVILEGE");
        Privilege updatePrivilege
                =createPrivilegeIfNotFound("UPDATE_PRIVILEGE");
        Privilege deletePrivilege
                =createPrivilegeIfNotFound("DELETE_PRIVILEGE");


        List<Privilege> adminPrivileges = Arrays.asList(
                readPrivilege, writePrivilege, updatePrivilege, deletePrivilege);
        createRoleIfNotFound("ROLE_ADMIN", adminPrivileges);

        List<Privilege> clientPrivileges = Arrays.asList(
                readPrivilege, writePrivilege, updatePrivilege, deletePrivilege);
        createRoleIfNotFound("ROLE_CLIENT", clientPrivileges);


        if (userRepository.findByEmail("admin@testowy.com") == null) {
            Role adminRole = roleRepository.findByName("ROLE_ADMIN");
            User adminUser = new User();
            adminUser.setUsername("Admin");
            adminUser.setName("Jan");
            adminUser.setSurname("Kowalski");
            adminUser.setPassword(passwordEncoder.encode("admin1234"));
            adminUser.setEmail("admin@testowy.com");
            adminUser.setPhoneNumber("123456789");
            adminUser.setRoles(Arrays.asList(adminRole));
            userRepository.save(adminUser);
        }

    }

    @Transactional
    Privilege createPrivilegeIfNotFound(String name) {

        Privilege privilege = privilegeRepository.findByName(name);
        if (privilege == null) {
            privilege = new Privilege(name);
            privilegeRepository.save(privilege);
        }
        return privilege;
    }

    @Transactional
    Role createRoleIfNotFound(
            String name, Collection<Privilege> privileges) {

        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
            role.setPrivileges(privileges);
            roleRepository.save(role);
        }
        return role;
    }
}
