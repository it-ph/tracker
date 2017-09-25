package com.personiv.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.personiv.dao.UserDao;
import com.personiv.model.User;
import com.personiv.model.UserDetailsImpl;

@Service
public class CustomUserDetailsService implements UserDetailsService{
	private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);
	
	
	@Autowired
	private UserDao userDao;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//User user = userService.getUserByUsername(username);
		User user = userDao.getUserByUsername(username);
		UserDetails userDetails = null;
		
		if (user == null) {
             logger.debug("user not found with the provided username");
             return null;
         }else {
        	 userDetails = new UserDetailsImpl(user);
         }
		
		return userDetails;
    
	}

}
