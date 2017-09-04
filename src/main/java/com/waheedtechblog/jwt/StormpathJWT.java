package com.waheedtechblog.jwt;

import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.crypto.MacProvider;

/**
 * This class will handle encoding/decoding and verification of JWT token using
 * Stormpath via Symmetric key.
 * 
 * @author abdulwaheed18@gmail.com
 *
 */
public class StormpathJWT {

	public static void main(String[] args) {

		StormpathJWT application = new StormpathJWT();

		Key key = MacProvider.generateKey();

		String jwtToken = application.createJWT(key);
		System.out.println("JWT: " + jwtToken + "\n");

		boolean isValid = application.isJWTValid(jwtToken, key);

		if (isValid) {
			System.out.println("JWT token is valid");
		} else {
			System.out.println("JWT token is not valid");
		}

		application.displayHeaders(jwtToken, key);

		application.displayClaims(jwtToken, key);

	}

	/*
	 * Will generate the key and signed it using specified key and Algorithms
	 */
	private String createJWT(Key key) {

		Claims claims = new DefaultClaims();
		claims.setSubject("Abdul");
		claims.setId("1234");
		claims.setIssuedAt(new Date());

		// you can add custom key as well
		claims.put("Customkey", "CustomValue");

		/*
		 * String jwtToken = Jwts.builder().setSubject("Abdul").setIssuedAt(new
		 * Date()) .signWith(SignatureAlgorithm.HS512, key).compact();
		 */
		// or

		String jwtToken = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS512, key).compact();

		return jwtToken;
	}

	/*
	 * Will verify weather the JWT token is valid or not
	 */
	private boolean isJWTValid(String jwtToken, Key key) {
		boolean isValid = false;
		try {
			Jwts.parser().setSigningKey(key).parseClaimsJws(jwtToken);
			isValid = true;
		} catch (SignatureException se) {
			System.err.println("Invalid token: " + se.getMessage());
		}
		return isValid;
	}

	/*
	 * 
	 * Will show you how you can retreive the header attribute from JWT.
	 */
	private void displayHeaders(String jwtToken, Key key) {
		System.out.println("\n Headers: ");
		JwsHeader<?> headers = Jwts.parser().setSigningKey(key).parseClaimsJws(jwtToken).getHeader();
		System.out.println("Algorithm:  " + headers.getAlgorithm());
	}

	/*
	 * Will show how you can retreive the claims from JWT
	 */
	private void displayClaims(String jwtToken, Key key) {
		System.out.println("\nClaims: ");
		Claims claim = Jwts.parser().setSigningKey(key).parseClaimsJws(jwtToken).getBody();
		System.out.println("Subject: " + claim.getSubject());
		System.out.println("Issued At: " + claim.getIssuedAt());
		System.out.println("Custom Key: " + claim.get("Customkey"));
	}

}
