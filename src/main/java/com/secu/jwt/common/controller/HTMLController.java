package com.secu.jwt.common.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HTMLController {

	@GetMapping("/html/**")
	public void goHtml() {}
	
	@GetMapping("/")
	public String home() {
		return "html/index";
	}
}
