package org.sid.secservice;

import org.sid.secservice.entities.AppRole;
import org.sid.secservice.entities.AppUser;
import org.sid.secservice.service.AuthService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecServiceApplication {

    public static void main(String[] args) {

        SpringApplication.run(SecServiceApplication.class, args);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner commandLineRunner(AuthService authService) {
        return args -> {
            authService.addUser(new AppUser(null,"user1","1234",new ArrayList<>()));
            authService.addUser(new AppUser(null,"user2","1234",new ArrayList<>()));
            authService.addUser(new AppUser(null,"admin","1234",new ArrayList<>()));

            authService.addRole(new AppRole(null,"USER"));
            authService.addRole(new AppRole(null,"ADMIN"));

            authService.addRoleToUser("user1","USER");
            authService.addRoleToUser("user2","USER");
            authService.addRoleToUser("admin","ADMIN");
        };
    }

}
