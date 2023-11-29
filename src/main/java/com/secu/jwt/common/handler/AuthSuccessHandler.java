package com.secu.jwt.common.handler;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.secu.jwt.common.provider.JWTProvider;
import com.secu.jwt.vo.LoginInfoVO;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthSuccessHandler implements AuthenticationSuccessHandler {

	private final JWTProvider jwtProvider;
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		// TODO Auto-generated method stub
		LoginInfoVO login = (LoginInfoVO)authentication.getPrincipal();
		JSONObject jsonObj = new JSONObject();
		String token = jwtProvider.generateJWT(login);
		response.setHeader("Authorization", "Bearer " + token);
		try {
			jsonObj.put("token", token);
		} catch (JSONException e) {
			e.printStackTrace();
		}
		response.setContentType("application/json;charset=UTF-8");
		response.setCharacterEncoding("UTF-8");
		PrintWriter out = response.getWriter();
		out.print(jsonObj);
		out.flush();
		out.close();
		
	}

}
