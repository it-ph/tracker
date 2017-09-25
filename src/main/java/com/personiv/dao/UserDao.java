package com.personiv.dao;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.personiv.model.Role;
import com.personiv.model.User;


@Repository
@Transactional(readOnly = false)
public class UserDao extends JdbcDaoSupport{
	
	private JdbcTemplate jdbcTemplate;

    @Autowired
    private DataSource dataSource;

    @PostConstruct
    private void initialize() {
        setDataSource(dataSource);
        jdbcTemplate = getJdbcTemplate();
    }
    
    
	public User getUser(String username, String password) {
		String sql = "Call _proc_getUserAccount(?,?)";
		User user = jdbcTemplate.queryForObject(sql,new Object[] {username,password}, new BeanPropertyRowMapper<User>(User.class));
		
		String sql2 = "Call _proc_getUserRolesById(?)";
		List<Role> roles = jdbcTemplate.query(sql2,new Object[] {user.getId()}, new BeanPropertyRowMapper<Role>(Role.class));
		
		Set<Role> r = new HashSet<>();
		
		for(Role rl: roles) {
			r.add(rl);
		}
		
		user.setRoles(r);
		
		return user;
	}


	public User findUserById(Integer id) {
		String sql = "Call findUserById(?);";
		System.out.println(sql);
		User user = jdbcTemplate.queryForObject(sql,new Object[] {id}, new BeanPropertyRowMapper<User>(User.class));
		
		if(user != null) {
			List<Role> roles = getRoles(user.getId());
			if(!roles.isEmpty()) {
				Set<Role> roles2 = new HashSet<>();
				for(Role r: roles) {
					roles2.add(r);
				}
				user.setRoles(roles2);
			}
		}
		return user;
	}
	public List<User>getUsers(){
		String query ="Call getUsers()";
		List<User> users =jdbcTemplate.query(query,new BeanPropertyRowMapper<User>(User.class));
		return users;
	}


	public User getUserByUsername(String username) {
		String sql = "Call _proc_getUserByUsername(?)";
		User user = jdbcTemplate.queryForObject(sql,new Object[] {username}, new BeanPropertyRowMapper<User>(User.class));	
		
		if(user != null) {
			
			String sql2 = "Call _proc_getUserRolesById(?)";
			List<Role> roles = jdbcTemplate.query(sql2,new Object[] {user.getId()}, new BeanPropertyRowMapper<Role>(Role.class));
			
			Set<Role> r = new HashSet<>();
			
			for(Role rl: roles) {
				r.add(rl);
			}
			
			user.setRoles(r);
		}
		
		return user;
	}


	public List<Role> getRoles(Integer id) {
		String query ="Call _proc_getUserRolesById(?)";
		List<Role> roles =jdbcTemplate.query(query,new Object[] {id},new BeanPropertyRowMapper<Role>(Role.class));
		return roles;
	}


	
}
