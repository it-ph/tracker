package com.personiv.model;

import java.sql.Date;
import java.util.Set;

import lombok.Data;

@Data
public class User {
	private Integer id;
	private String username;
	private String userpass;
	private Date created;
	private Date updated;
	private Date deleted;
	private Set<Role> roles;
	private boolean accountNonLocked;
	private boolean accountNonExpired;
	private boolean credentialsNonExpired;
	private boolean enabled;
}
