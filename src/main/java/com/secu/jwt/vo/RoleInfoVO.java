package com.secu.jwt.vo;

import org.springframework.security.core.GrantedAuthority;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RoleInfoVO implements GrantedAuthority {
	private static final long serialVersionUID = 1L;
	private String riCode;

	@Override
	public String getAuthority() {
		
		return riCode;
	}
	
}
