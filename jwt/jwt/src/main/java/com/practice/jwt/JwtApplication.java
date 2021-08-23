package com.practice.jwt;

import com.practice.jwt.Utils.ART;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
		System.out.println(ART.header);
	}

}
