package com.evergreen.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JWTUtil {
	private String TOKEN_SECRET_KEY="secret";
	
	public String extractUserName(String token){
		return extractClaim(token,Claims::getSubject);
	}
	
	public Date extractExpiration(String token){
		return extractClaim(token,Claims::getExpiration);
	}
	
	public <T> T extractClaim(String token,Function<Claims,T> claimResolver){
		final Claims claim=extractAllClaims(token);
		return claimResolver.apply(claim);
	}
	
	private Claims extractAllClaims(String token){
		return Jwts.parser().setSigningKey(TOKEN_SECRET_KEY).parseClaimsJws(token).getBody();
	}
	
	private boolean isTokenExpired(String token) {
		// TODO Auto-generated method stub
		return extractExpiration(token).before(new Date());
	}
	
	public String generateToken(UserDetails user){
		Map<String,Object> claims=new HashMap<>();
		return createToken(claims, user.getUsername());				
	}
	
	private String createToken(Map<String,Object> claims,String subject){
		return Jwts.builder().setClaims(claims).setSubject(subject)
					.setIssuedAt(new Date(System.currentTimeMillis()))
						.setExpiration(new Date(System.currentTimeMillis() + 1000 *60 * 60 * 10))
							.signWith(SignatureAlgorithm.HS256, TOKEN_SECRET_KEY).compact();
	}
	
	public boolean validateToken(String token,UserDetails user){
		final String username= extractUserName(token);
		return (username.equals(user.getUsername()) && !isTokenExpired(token));
	}

	
}
