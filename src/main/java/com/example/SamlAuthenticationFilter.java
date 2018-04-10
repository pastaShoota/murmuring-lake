package com.example;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class SamlAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static final Logger LOGGER = LoggerFactory.getLogger(SamlAuthenticationFilter.class);
	
	private static final String SAML_RESPONSE_PARAM = "SAMLResponse";
	private static final Pattern BASE_64_PATTERN = Pattern.compile("[a-zA-Z0-9+/]+={0,2}$");
	
	public SamlAuthenticationFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		String samlResponse = request.getParameter(SAML_RESPONSE_PARAM);
		Authentication authentication = new UsernamePasswordAuthenticationToken("toto", samlResponse);
		
		LOGGER.debug("Attempting to authenticate based on SAML response {}", samlResponse);
		authentication = getAuthenticationManager().authenticate(authentication);

		LOGGER.debug("attempt Authentication result: {}", authentication.toString());
		return authentication;
	}

	@Override
	public boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String samlResponse = request.getParameter(SAML_RESPONSE_PARAM);
		
		return super.requiresAuthentication(request, response)
				&& (authentication == null || !authentication.isAuthenticated())
				&& samlResponse != null 
				&& BASE_64_PATTERN.matcher(samlResponse).matches()
				;
	}
	
}
