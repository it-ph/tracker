package com.personiv.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.personiv.config.filter.JwtAuthenticationTokenFilter;
import com.personiv.service.CustomUserDetailsService;


@Configurable
@EnableWebSecurity
public class WebConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	CustomUserDetailsService userDetailsService;
	
	@Autowired
	private DataSource dataSource;
	// This method is for overriding the default AuthenticationManagerBuilder.
	// We can specify how the user details are kept in the application. It may
	// be in a database, LDAP or in memory.
	
	
    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        return new JwtAuthenticationTokenFilter();
    }

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth
//		// using in memory authentication
//		.inMemoryAuthentication()
//		// adding Administrator user
//		.withUser("admin").password("admin").authorities("ADMIN", "USER")
//		// using add() method for adding new user
//		.and()
//		// adding a user without Administrator authority
//		.withUser("user").password("user").authorities("USER");
		
		auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(new BCryptPasswordEncoder());
		//auth.jdbcAuthentication().dataSource(dataSource);
	}

	// This method is for overriding some configuration of the WebSecurity
	// If you want to ignore some request or request patterns then you can
	// specify that inside this method
	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}

	// This method is used for override HttpSecurity of the web Application.
	// We can specify our authorization criteria inside this method.
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	
			// starts authorizing configurations
		http.authorizeRequests()
			// ignore the "/" and "/index.html"
			.antMatchers("/", "/authenticate","/token-test","/app/app.js", "/css/**").permitAll()
			// following URL is only accessible for ADMIN users
			.antMatchers("/admin-files/**").hasAuthority("ADMIN")
			// following URL is only accessible users how has either USER or ADMIN authority
			.antMatchers("/user-files/**").hasAnyAuthority("USER","ADMIN")
			// authenticate all remaining URLS
			.anyRequest().fullyAuthenticated().and()
			// enabling the basic authentication
			//.httpBasic().and()
			// configuring the session as state less. Which means there is
			// no session in the server
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
			// disabling the CSRF - Cross Site Request Forgery
			.csrf().disable();
		
		  //JWT Custom filter
		http.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);
	
		// disable page caching
		http.headers().cacheControl();
		
   
		
	}

	
}
