package com.security.oauthserver.entity;

import jakarta.persistence.*;

import java.util.List;

@Entity
public class Privilege {

    public Privilege() {}

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer privilegeId;
    private String name;

    @ManyToMany(mappedBy = "privileges")
    private List<Role>roles;

    public Privilege(String name) {
        this.name = name;
    }

    public Integer getPrivilegeId() {
        return privilegeId;
    }

    public void setPrivilegeId(Integer privilegeId) {
        this.privilegeId = privilegeId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }
}
