package com.secu.jwt.mapper;

import java.util.List;

import com.secu.jwt.vo.RoleInfoVO;

public interface RoleInfoMapper {

	List<RoleInfoVO> selectRoleInfoByliNum(int liNum);
}
