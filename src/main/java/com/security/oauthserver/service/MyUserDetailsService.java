package com.security.oauthserver.service;

import com.security.oauthserver.entity.Privilege;
import com.security.oauthserver.entity.Role;
import com.security.oauthserver.entity.User;
import com.security.oauthserver.exception.EmailExistsException;
import com.security.oauthserver.repository.RoleRepository;
import com.security.oauthserver.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
        User user=userRepository.findByEmailId(emailId).orElse(null);
        if(user==null){
            return null;
        }
        return new org.springframework.security.core.userdetails.User(
                user.getEmailId(),user.getPassword(),user.getEnabled(),true,true,true,getAuthorities(user.getRoles())
        );
    }

    private Collection<? extends GrantedAuthority> getAuthorities(List<Role>roles){
        return getGrantedAuthorities(getPrivileges(roles));
    }
    private List<String> getPrivileges(List<Role>roles){
        List<String>privileges=new ArrayList<>();
        List<Privilege>collection=new ArrayList<>();

        for(Role role:roles){
            privileges.add(role.getName());
            collection.addAll(role.getPriviliges());
        }
        for(Privilege item:collection){
            privileges.add(item.getName());
        }
        return privileges;
    }

    public List<GrantedAuthority> getGrantedAuthorities(List<String>privileges){
        List<GrantedAuthority> authorities=new ArrayList<>();
        for(String privilege:privileges){
            authorities.add(new SimpleGrantedAuthority(privilege));
        }
        return authorities;
    }

    public boolean checkEmailIdIfExists(String emailId) {
        return userRepository.existsByEmailId(emailId);
    }

    public User registerNewUserAccount(User userDto) throws EmailExistsException {

        if (checkEmailIdIfExists(userDto.getEmailId())) {
            throw new EmailExistsException
                    ("There is an account with that email adress: " + userDto.getEmailId());
        }
        User user = new User(userDto.getFirstName(),userDto.getLastName(),passwordEncoder.encode(userDto.getPassword()),userDto.getEnabled());

        user.setRoles(Arrays.asList(roleRepository.findRoleByName("ROLE_USER").orElse(null)));
        return userRepository.save(user);
    }
}