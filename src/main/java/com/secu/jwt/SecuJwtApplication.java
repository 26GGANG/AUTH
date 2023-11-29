package com.secu.jwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan
public class SecuJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecuJwtApplication.class, args);
	}

}
