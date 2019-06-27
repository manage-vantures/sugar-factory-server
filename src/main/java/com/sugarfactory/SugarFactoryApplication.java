package com.sugarfactory;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = {SecurityAutoConfiguration.class })
public class SugarFactoryApplication {
	public static void main(String[] args) {
		SpringApplication.run(SugarFactoryApplication.class, args);
	}

}
