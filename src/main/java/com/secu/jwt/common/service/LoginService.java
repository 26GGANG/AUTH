package com.secu.jwt.common.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.secu.jwt.mapper.LoginInfoMapper;
import com.secu.jwt.mapper.RoleInfoMapper;
import com.secu.jwt.vo.LoginInfoVO;

import lombok.RequiredArgsConstructor;
@Service
@RequiredArgsConstructor
public class LoginService implements UserDetailsService {
	
	private final LoginInfoMapper loginMapper;
	private final RoleInfoMapper roleMapper;
	@Override
	public LoginInfoVO loadUserByUsername(String liId) throws UsernameNotFoundException {
		LoginInfoVO user = loginMapper.selectLoginInfoByLiId(liId);
		if(user==null) {
			throw new UsernameNotFoundException("아이디 비밀번호를 확인");
		}
		user.setAuthorities(roleMapper.selectRoleInfoByliNum(user.getLiNum()));
		return user;
	}

}
