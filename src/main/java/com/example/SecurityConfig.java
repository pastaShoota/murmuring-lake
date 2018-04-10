package com.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("fuck")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/stylesheets/**","/webjars/**","/images/**","/js/**")
			.permitAll()
			.anyRequest().authenticated()
		.and()
			.formLogin()
			.loginPage("/login")
			.permitAll()
			.defaultSuccessUrl("/")
		.and()
			.logout()
			.invalidateHttpSession(true)
			.clearAuthentication(true)
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.logoutSuccessUrl("/login?logout")
			.permitAll()
		.and()
			.addFilterBefore(samlAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
		;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(samlAuthenticationProvider());
	}

	@Bean
	public SamlAuthenticationProvider samlAuthenticationProvider() {
		return new SamlAuthenticationProvider();
	}
	
	@Bean
	public SamlAuthenticationFilter samlAuthenticationFilter() throws Exception {
		SamlAuthenticationFilter filter = new SamlAuthenticationFilter("/login");
		filter.setAuthenticationManager(authenticationManagerBean());
		filter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return filter;
	}
	
	@Bean
	public AuthenticationFailureHandler authenticationFailureHandler() {
		return new SimpleUrlAuthenticationFailureHandler("/login?error");
	}
}
