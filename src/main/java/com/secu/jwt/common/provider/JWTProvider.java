package com.secu.jwt.common.provider;

import java.security.Key;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.secu.jwt.mapper.LoginInfoMapper;
import com.secu.jwt.mapper.RoleInfoMapper;
import com.secu.jwt.vo.LoginInfoVO;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
@Component
public class JWTProvider {
	
	private final String secret;
	private final int expire;
	private final LoginInfoMapper liMapper;
	private final RoleInfoMapper riMapper;
	
//	public static void main(String[] args) {
//		JWTProvider jwt = new JWTProvider("rlaghdrbsrlaalswn.3791-khk", 3600000);
//		LoginInfoVO login = new LoginInfoVO();
//		login.setLiId("TEST");
//		login.setLiName("홍길동");
//		login.setLiNum(1);
//		String token = jwt.generateJWT(login);
//		System.out.println(token);
//	}
	
	public JWTProvider(@Value("${jwt.secret}") String secret,
			@Value("${jwt.expire}") int expire, LoginInfoMapper liMapper, RoleInfoMapper riMapper) {
		this.secret = secret;
		this.expire = expire;
		this.liMapper = liMapper;
		this.riMapper = riMapper;
	}
	
	public String generateJWT(LoginInfoVO login) {
		Map<String,Object> claims = new HashMap<>();
		claims.put("liId", login.getLiId());
		claims.put("liName", login.getLiName());
		claims.put("liNum", login.getLiNum());
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MILLISECOND, expire);
		byte[] bytes = DatatypeConverter.parseBase64Binary(secret);
		Key key = new SecretKeySpec(bytes, SignatureAlgorithm.HS256.getJcaName());
		JwtBuilder jb = Jwts.builder()
				.setClaims(claims)
				.signWith(SignatureAlgorithm.HS256, key)
				.setExpiration(c.getTime());
		return jb.compact();
	}
	
	public int getExpire() {
		return expire;
	}
	
	public String generateJWT(String liId) {
		Map<String,Object> claims = new HashMap<>();
		
		LoginInfoVO login = liMapper.selectLoginInfoByLiId(liId);
		login.setAuthorities(riMapper.selectRoleInfoByliNum(login.getLiNum()));
		
		claims.put("liId", login.getLiId());
		claims.put("liName", login.getLiName());
		claims.put("liNum", login.getLiNum());
		claims.put("authorities", login.getAuthorities());
		
		Calendar c = Calendar.getInstance();
		c.add(Calendar.MILLISECOND, expire);
		byte[] bytes = DatatypeConverter.parseBase64Binary(secret);
		Key key = new SecretKeySpec(bytes, SignatureAlgorithm.HS256.getJcaName());
		
		JwtBuilder jb = Jwts.builder()
				.setClaims(claims)
				.signWith(SignatureAlgorithm.HS256, key)
				.setExpiration(c.getTime());
				
		return jb.compact();
	}
	
	private Claims getClaims(String token) {
		Claims claims = Jwts.parser()
				.setSigningKey(DatatypeConverter.parseBase64Binary(secret))
				.parseClaimsJwt(token).getBody();
		return claims;
	}
	
	public boolean validateJWT(String token) {
		try {
			getClaims(token);
			return true;
		} catch(Exception e) {
			return false;
		}
	}
	
	public LoginInfoVO getLogin(String token) {
		if(validateJWT(token)) {
			Claims claims = getClaims(token);
			LoginInfoVO login = new LoginInfoVO();
			login.setLiId(claims.get("liId").toString());
			login.setLiName(claims.get("liName").toString());
			login.setLiNum(Integer.parseInt(claims.get("liNum").toString()));
			return login;
		}
		return null;
	}
}
