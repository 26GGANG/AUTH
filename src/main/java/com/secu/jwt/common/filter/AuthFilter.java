package com.secu.jwt.common.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secu.jwt.common.provider.JWTProvider;
import com.secu.jwt.vo.LoginInfoVO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class AuthFilter extends UsernamePasswordAuthenticationFilter{
	
	
	private final JWTProvider jwtProvider;
	
	public AuthFilter(AuthenticationManager authManager, JWTProvider jwtProvider) {
		setAuthenticationManager(authManager);
		this.jwtProvider = jwtProvider;
	}
	

	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		try {
			ObjectMapper om = new ObjectMapper();
			LoginInfoVO login = om.readValue(request.getInputStream(), LoginInfoVO.class);
			UsernamePasswordAuthenticationToken authToken =
					new UsernamePasswordAuthenticationToken(login.getLiId(), login.getLiPwd(), login.getAuthorities());
			setDetails(request, authToken);
			
			String liId = authToken.getPrincipal().toString();
			ResponseCookie resCookie = ResponseCookie.from("Authorization", jwtProvider.generateJWT(liId))
				.httpOnly(true)
				.sameSite("None")
				.secure(true)
				.path("/")
				.maxAge(Math.toIntExact(jwtProvider.getExpire()))
				.build();
			response.addHeader("Set-Cookie", resCookie.toString());
			
			return getAuthenticationManager().authenticate(authToken);
		}catch(Exception e) {
			throw new BadCredentialsException(null);
		}
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
		LoginInfoVO login = (LoginInfoVO) authResult.getPrincipal();
		String token = jwtProvider.generateJWT(login);
		Map<String,String> res = new HashMap<>();
		res.put("jwt", token);
		JSONObject jsonObj = new JSONObject(res);
		response.setContentType("application/json;charset=UTF-8");
		PrintWriter out = response.getWriter();
		out.print(jsonObj);
		out.flush();
		out.close();
	}
	
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
		response.sendRedirect("/");
	}
	
}
