package com.security.oauthserver.entity;
import jakarta.persistence.*;

import java.util.List;

@Entity
public class Role {

    public Role() {
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer roleId;
    private String name;

    @ManyToMany(mappedBy = "roles")
    private List<User>users;

    @ManyToMany
    @JoinTable(
            name="roles_privileges",
            joinColumns=@JoinColumn(name="roleId"),
            inverseJoinColumns = @JoinColumn(name="priviligeId")

    )
    private List<Privilege> privileges;

    public Role(String name) {
        this.name = name;
    }

    public Role(String name, List<Privilege> privileges) {
        this.name = name;
        this.privileges = privileges;
    }

    public Integer getRoleId() {
        return roleId;
    }

    public void setRoleId(Integer roleId) {
        this.roleId = roleId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<Privilege> getPriviliges() {
        return privileges;
    }

    public void setPriviliges(List<Privilege> privileges) {
        this.privileges = privileges;
    }
}
