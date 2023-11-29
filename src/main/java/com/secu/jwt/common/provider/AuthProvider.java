package com.secu.jwt.common.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.secu.jwt.common.service.LoginService;
import com.secu.jwt.vo.LoginInfoVO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@RequiredArgsConstructor
@Slf4j
public class AuthProvider implements AuthenticationProvider {

	private final LoginService loginService;
	private final PasswordEncoder passwordEncoder;
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken)authentication;
		String liId = token.getName();
		String liPwd = token.getCredentials().toString();
		LoginInfoVO login = loginService.loadUserByUsername(liId);
		if(!passwordEncoder.matches(liPwd, login.getPassword()) ){
			throw new BadCredentialsException("login fail");
		}
		return new UsernamePasswordAuthenticationToken(login, liPwd, login.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
	
}
