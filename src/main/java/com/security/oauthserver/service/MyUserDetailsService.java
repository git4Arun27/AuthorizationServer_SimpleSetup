package com.security.oauthserver.service;

import com.security.oauthserver.dto.UserDto;
import com.security.oauthserver.entity.Privilege;
import com.security.oauthserver.entity.Role;
import com.security.oauthserver.entity.User;
import com.security.oauthserver.exception.EmailExistsException;
import com.security.oauthserver.repository.RoleRepository;
import com.security.oauthserver.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.swing.text.html.HTMLDocument;
import java.util.*;

@Service
@Transactional
public class MyUserDetailsService implements UserDetailsService {
    Logger logger = LoggerFactory.getLogger(MyUserDetailsService.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private static final String ROLE_PREFIX="ROLE_";

    public MyUserDetailsService(UserRepository userRepository, RoleRepository roleRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {
        User user= null;
        try {
            user = userRepository.findByEmailId(emailId).orElseThrow(()->new ClassNotFoundException("User NOT FOUND"));
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        if(user==null){
            return null;
        }
        List<Role>roles=user.getRoles();
        logger.error("ROLES: {}",roles);
        return new org.springframework.security.core.userdetails.User(
                user.getEmailId(),user.getPassword(),user.getEnabled(),true,true,true,getAuthorities(roles)
        );
    }

    private Collection<? extends GrantedAuthority> getAuthorities(List<Role>roles){
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        roles.forEach(
                role->{
                    if(role!=null){
                        grantedAuthorities.add(new SimpleGrantedAuthority(ROLE_PREFIX+role.getName()));
                        List<Privilege>privileges=role.getPriviliges();
                        if(privileges!=null){
                            privileges.forEach(
                                    privilege -> grantedAuthorities.add(new SimpleGrantedAuthority(privilege.getName()))
                            );
                        }
                    }
                }
        );
        return grantedAuthorities;


       //return getGrantedAuthorities(getPrivileges(roles));
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

    public User registerNewUserAccount(UserDto userDto) throws EmailExistsException {

        if (checkEmailIdIfExists(userDto.getEmailId())) {
            throw new EmailExistsException
                    ("There is an account with that email adress: " + userDto.getEmailId());
        }
        User user = new User(userDto.getFirstName(),userDto.getLastName(),userDto.getEmailId(),passwordEncoder.encode(userDto.getPassword()),userDto.getEnabled());
        user.setRoles(Arrays.asList(roleRepository.findRoleByName("ROLE_USER").orElse(null)));
        return userRepository.save(user);
    }
}