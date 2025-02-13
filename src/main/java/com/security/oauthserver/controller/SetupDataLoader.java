package com.security.oauthserver.controller;

import com.security.oauthserver.entity.Privilege;
import com.security.oauthserver.entity.Role;
import com.security.oauthserver.entity.User;
import com.security.oauthserver.repository.PrivilegeRepository;
import com.security.oauthserver.repository.RoleRepository;
import com.security.oauthserver.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    boolean alreadySetup=false;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PrivilegeRepository privilegeRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent event) {

        if(alreadySetup) return;

        Privilege readPrivilege=createPriviligeIfNotExists("READ_PRIVILEGE");
        Privilege writePrivilege=createPriviligeIfNotExists("WRITE_PRIVILEGE");

        Role adminRole=createRoleIfNotExists("ROLE_ADMIN");
        Role userRole=createRoleIfNotExists("ROLE_USER");

        List<Privilege>adminPrivilege= Arrays.asList(readPrivilege,writePrivilege);

        adminRole.setPriviliges(adminPrivilege);

        userRole.setPriviliges(Arrays.asList(readPrivilege));


        User user=new User("arun","prakash","arun.com",passwordEncoder.encode("123"),true);
        user.setTokenExpired(false);
        user.setRoles(Arrays.asList(adminRole,userRole));
        userRepository.save(user);

        alreadySetup=true;

    }

    @Transactional
    public Privilege createPriviligeIfNotExists(String name){
        Privilege privilege=privilegeRepository.findPrivilegeByName(name).orElse(null);
        if(privilege==null){
            privilege=new Privilege(name);
            privilegeRepository.save(privilege);
        }
        return privilege;
    }

    @Transactional
    public Role createRoleIfNotExists(String name){
        Role role=roleRepository.findRoleByName(name).orElse(null);
        if(role==null){
            role=new Role(name);
            roleRepository.save(role);
        }
        return role;
    }

}
