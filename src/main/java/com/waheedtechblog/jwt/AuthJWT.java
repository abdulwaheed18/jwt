package com.waheedtechblog.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Dummy application
 * 
 * This class will handle encoding/decoding and verification of JWT token using
 * Auth0 library via Asymmetric key
 * 
 * @author abdulwaheed18@gmail.com
 *
 */
public class AuthJWT {

	public static void main(String[] args) throws Exception {

		AuthJWT authJWT = new AuthJWT();

		Map<String, Object> keys = authJWT.getRSAKeys();

		RSAPrivateKey privateKey = (RSAPrivateKey) keys.get("private");
		RSAPublicKey publicKey = (RSAPublicKey) keys.get("public");

		String token = null;
		try {
			// pass the privatekey for encryption
			Algorithm algorithm = Algorithm.RSA256(null, privateKey);

			// Signing via Symmetric key
			// Algorithm algorithm = Algorithm.HMAC256("secret");
			token = JWT.create().withIssuer("auth0").withSubject("Abdul").sign(algorithm);
		} catch (JWTCreationException exception) {
			// Invalid Signing configuration / Couldn't convert Claims.
		}
		System.out.println("JWT Token: \n" + token);

		DecodedJWT jwt = null;
		try {
			// decode it using public key
			Algorithm algorithm = Algorithm.RSA256(publicKey, null);
			JWTVerifier verifier = JWT.require(algorithm).withIssuer("auth0").build(); // Reusable
																						// verifier
																						// instance
			jwt = verifier.verify(token);
		} catch (JWTVerificationException exception) {
			// Invalid signature/claims
		}

		// fetch the claims
		System.out.println("Subject: " + jwt.getSubject());
		System.out.println("Issuer: " + jwt.getIssuer());
	}

	// Get RSA keys. Uses key size of 2048.
	private Map<String, Object> getRSAKeys() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		Map<String, Object> keys = new HashMap<String, Object>();
		keys.put("private", privateKey);
		keys.put("public", publicKey);
		return keys;
	}

}
