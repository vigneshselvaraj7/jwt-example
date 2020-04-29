package com.evergreen.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.evergreen.model.AuthenticationRequest;
import com.evergreen.model.AuthenticationResponse;
import com.evergreen.services.MyUserDetailsService;
import com.evergreen.util.JWTUtil;



@RestController
public class JWTRestController {

	@Autowired
	private AuthenticationManager authManager;
	
	@Autowired
	private MyUserDetailsService userService;
	
	@Autowired
	private JWTUtil jwt;
	
	@RequestMapping({ "/greet" })
	public String hello(){
		return "Hello world!";
	}
	
	@RequestMapping(value="/authenticate",method=RequestMethod.POST)
	public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) throws Exception{
		try{
			authManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword()));
		}catch(BadCredentialsException e){
			throw new Exception("Wrong credentials");
		}
		
		UserDetails user=userService.loadUserByUsername(request.getUserName());
		String token = jwt.generateToken(user);
		return ResponseEntity.ok(new AuthenticationResponse(token));
	}
}
