package com.evergreen.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.evergreen.util.JWTUtil;

@Component
public class JWTRequestFilter extends OncePerRequestFilter{

	@Autowired
	private UserDetailsService service;
	@Autowired
	private JWTUtil util;
	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filter)
			throws ServletException, IOException {
		final String authorizationHeader = req.getHeader("Authorization");
		String userName=null;
		String token=null;
		
		if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
			token=authorizationHeader.substring(7);
			userName = util.extractUserName(token);
		}
		
		if(userName != null && SecurityContextHolder.getContext().getAuthentication()== null){
			UserDetails user = service.loadUserByUsername(userName);
			if(util.validateToken(token, user)){
				UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(
						user,null,user.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		
		filter.doFilter(req, res);
		
	}

}
