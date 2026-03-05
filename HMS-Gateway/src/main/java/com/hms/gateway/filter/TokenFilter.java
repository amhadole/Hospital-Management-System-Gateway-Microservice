 package com.hms.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class TokenFilter extends AbstractGatewayFilterFactory<TokenFilter.Config>{
	
	private static final String SECRET = "b62003e2e5c4a7cec3c32d81932ccf838553a77fc4e92363687c42ee0fe1686aeb562ac0b87b5f33ad9b244fa4a5acf14429e08bcbad411a77a3177487774e7c";


	public TokenFilter() {
		super(Config.class);
	}
	
	public static class Config{
		
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain)->{
				String path = exchange.getRequest().getPath().toString();
				if(path.equals("/user/login")|| path.equals("/user/register")) {
					return chain.filter(exchange.mutate().request(r->r.header("X-Secret-Key", "SECRET")).build());
				}
				HttpHeaders headers = exchange.getRequest().getHeaders();
				if(!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
					throw new RuntimeException("Authorization header is missing");
				}
				String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
				if(authHeader == null || !authHeader.startsWith("Bearer")) {
					throw new RuntimeException("Authorization header is invalid");
				}
				String token = authHeader.substring(7);
				try {
					Claims claims = Jwts.parser().setSigningKey(SECRET).build().parseClaimsJws(token).getBody();
					exchange = exchange.mutate().request(r->r.header("X-Secret-Key", "SECRET")).build();
				}catch(Exception e) {
					throw new RuntimeException("Token is invalid");
				}
				return chain.filter(exchange);
		};
	}

}
