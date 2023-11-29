package com.secu.jwt.common.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.secu.jwt.common.provider.JWTProvider;
import com.secu.jwt.vo.LoginInfoVO;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class AuthorizationFilter extends OncePerRequestFilter {
	
	private final JWTProvider jwtProvider;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token = request.getHeader(HttpHeaders.AUTHORIZATION);
		boolean isCookie = false;
		
		if(token == null || token.isEmpty()) {
			if(request.getCookies() != null) {
				Cookie[] cookies = request.getCookies();
				for(Cookie cookie : cookies) {
					if("Authorization".equals(cookie.getName())) {
						token = cookie.getValue();
						break;
					}
				}
				isCookie = true;
			} else {
				filterChain.doFilter(request, response);
				return;
			}
		}
		try {
			token = token.replace("Bearer", "");
			if(jwtProvider.validateJWT(token)) {
				LoginInfoVO login = jwtProvider.getLogin(token);
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
						login.getLiId(), null, login.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
				filterChain.doFilter(request, response);
			}
		} catch (Exception e) {
			if(isCookie) {
				
			}
			response.setCharacterEncoding("UTF-8");
			response.setContentType("application/json");
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			PrintWriter out = response.getWriter();
			Map<String,String> res = new HashMap<>();
			res.put("msg", "토큰에 오류가 있습니다.");
			log.info("error=>{}", e);
			out.print(new JSONObject(res));
			out.flush();
			out.close();
		}
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		String[] excludePath = {"/api/**"};
		String path = request.getRequestURI();
		return Arrays.stream(excludePath).anyMatch(path::startsWith);
	}

}
