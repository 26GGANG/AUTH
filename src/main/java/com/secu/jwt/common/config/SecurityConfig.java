package com.secu.jwt.common.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.secu.jwt.common.filter.AuthFilter;
import com.secu.jwt.common.handler.AuthFailureHandler;
import com.secu.jwt.common.handler.AuthSuccessHandler;
import com.secu.jwt.common.provider.AuthProvider;
import com.secu.jwt.common.provider.JWTProvider;
import com.secu.jwt.common.service.LoginService;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
	
	private final PasswordEncoder passwordEncoder;
	private final JWTProvider jwtProvider;
	private final LoginService liService;
	
	@Bean AuthFailureHandler authFailureHandler() {
		return new AuthFailureHandler();
	}

	@Bean AuthSuccessHandler authSuccessHandler() {
		return new AuthSuccessHandler(jwtProvider);
	}
	
	@Bean
	AuthFilter authFilter() {
		AuthFilter authFilter = new AuthFilter(authenticationManager(), jwtProvider);
		authFilter.setFilterProcessesUrl("/auth/login");
		authFilter.afterPropertiesSet();
		return authFilter;
	}
	
	@Bean
	AuthProvider authProvider() {
		return new AuthProvider(liService, passwordEncoder);
	}
	
	@Bean
	AuthenticationManager authenticationManager() {
		return new ProviderManager(authProvider());
	}
	@Bean
	WebSecurityCustomizer webSecurityCustomizrer() {
		return (web)->{
			web.ignoring().antMatchers("/js/**","/css/**","/imgs/**","/auth/**","/html/auth/**","/");
		};
	}
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity hs) throws Exception {
		hs.authorizeHttpRequests((auth)-> auth
				.antMatchers("/html/test")
				.hasRole("ADMIN")
				.anyRequest()
				.authenticated());
		hs.csrf(csrf -> csrf.disable());
		hs.formLogin(login  -> login.disable());
		hs.addFilterBefore(authFilter(), UsernamePasswordAuthenticationFilter.class);
		hs.sessionManagement(management -> 
			management.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		return hs.build();
	}
}
