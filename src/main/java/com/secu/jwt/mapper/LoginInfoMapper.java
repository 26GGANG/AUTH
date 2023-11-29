package com.secu.jwt.mapper;

import com.secu.jwt.vo.LoginInfoVO;

public interface LoginInfoMapper {

	LoginInfoVO selectLoginInfoByLiId(String liId);
	
	int insertLoginInfo(LoginInfoVO login);
}
