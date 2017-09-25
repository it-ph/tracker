package com.personiv.controller;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mobile.device.Device;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.personiv.model.User;
import com.personiv.security.JwtAuthenticationResponse;
import com.personiv.service.CustomUserDetailsService;
import com.personiv.utils.JwtTokenUtil;

@RestController
public class TestController {

	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	
	@RequestMapping("/user")
	public Principal sayHello(Principal principal) {
		return principal;
	}
	
	@RequestMapping("/password")
	public String password() {
		BCryptPasswordEncoder b = new BCryptPasswordEncoder();
		String hash = b.encode("123");
		return hash;
	}
   
	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping("/admin-files")
	public String testAdmin( ) {
		return "admin resource";
	}
	
	@RequestMapping("/secure/greeting")
	public String greeting( ) {
		return "test Greeting";
	}
	
	@RequestMapping("/user-files")
	public String testUser() {
		return "user resource";
	}
	@RequestMapping("/token-test")
	public String tokenTest(String token) {
		System.out.println(token);
		String username = jwtTokenUtil.getUsernameFromToken(token);
		return username;
	}
   @RequestMapping(value = "authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(User user, Device device) throws AuthenticationException {

//        // Perform the security
//        final Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        user.getUsername(),
//                        user.getUserpass()
//                )
//        );
//        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Reload password post-security so we can generate token
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        
        String token = jwtTokenUtil.generateToken(userDetails, device);
        
        System.out.println("USER: "+user.getUsername());
        return ResponseEntity.ok(new JwtAuthenticationResponse(token));
    }
   
   @RequestMapping(value = "/refresh-token", method = RequestMethod.GET)
   public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
       
	   String token = request.getHeader("Authorization");
     
       if (jwtTokenUtil.canTokenBeRefreshed(token)) {
           String refreshedToken = jwtTokenUtil.refreshToken(token);
           return ResponseEntity.ok(new JwtAuthenticationResponse(refreshedToken));
       } else {
           return ResponseEntity.badRequest().body(null);
       }
   }
}
