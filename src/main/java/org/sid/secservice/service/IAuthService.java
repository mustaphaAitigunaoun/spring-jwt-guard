package org.sid.secservice.service;

import org.sid.secservice.entities.AppRole;
import org.sid.secservice.entities.AppUser;

import java.util.List;

public interface IAuthService {
    public AppUser addUser(AppUser appUser);
    public AppRole addRole(AppRole appRole);
    public AppUser findUserByUsername(String username);
    public AppRole findRoleByRoleName(String RoleName);
    public void addRoleToUser(String username,String roleName);
    public List<AppUser> getAllUser();
}
