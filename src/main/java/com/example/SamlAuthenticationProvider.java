package com.example;

import java.util.Collections;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * SAML based Authentication
 * 
 * @author ng6f8b9
 *
 */
public class SamlAuthenticationProvider implements AuthenticationProvider {
	private static final Logger LOGGER = LoggerFactory.getLogger(SamlAuthenticationProvider.class);

	private static final String CERTIFICATE ="MIIBrTCCAaGgAwIBAgIBATADBgE......";
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String samlResponse, username;
		try {
			samlResponse = authentication.getCredentials().toString();
		} catch(ClassCastException | NullPointerException e) {
			LOGGER.info("Unexpected authentication type. Let other providers take over Authentication");
			return null;
		}
		// FIXME use onelogin toolkit to check SAML response validity
		if (!samlResponse.contains("valid")) {
			LOGGER.info("SAML Authentication failed: invalid SAML response");
			throw new BadCredentialsException("Invalid SAML response");
		}
		username = samlResponse.split("valid")[0];
		LOGGER.info("SAML Authentication succeeded");
		Authentication auth = new UsernamePasswordAuthenticationToken(username, samlResponse, Collections.singleton(new SimpleGrantedAuthority("USER")));
		return auth;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}

}
