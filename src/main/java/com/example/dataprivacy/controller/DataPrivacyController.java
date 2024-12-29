package com.example.dataprivacy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DataPrivacyController {  //REST Controller for REST API

	@GetMapping("/welcome")
	public String welcome() {
		
		return "Welcome to the Data Privacy and Security System" ;
	} 
	
	
}
