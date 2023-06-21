package com.example.security;

import com.example.security.auth.AuthenticationService;
import com.example.security.auth.RegisterRequest;
import com.example.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.example.security.user.Role.*;

@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthenticationService service) {
        return args -> {
            var admin = RegisterRequest.builder()
                    .firstName("Admin")
                    .lastName("Admin")
                    .email("admin@gmail.com")
                    .password("password")
                    .role(ADMIN)
                    .build();
            System.out.println("Admin token: " + service.register(admin).getToken());

            var manager = RegisterRequest.builder()
                    .firstName("Manager")
                    .lastName("Manager")
                    .email("manager@gmail.com")
                    .password("password")
                    .role(MANAGER)
                    .build();
            System.out.println("Manager token: " + service.register(manager).getToken());

            var user = RegisterRequest.builder()
                    .firstName("User")
                    .lastName("User")
                    .email("user@gmail.com")
                    .password("password")
                    .role(USER)
                    .build();
            System.out.println("User token: " + service.register(user).getToken());
        };
    }
}
