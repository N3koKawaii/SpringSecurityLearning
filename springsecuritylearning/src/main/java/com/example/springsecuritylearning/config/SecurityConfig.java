package com.example.springsecuritylearning.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class SecurityConfig {
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder){
        UserDetails user = User.withUsername("user")
                .password(encoder.encode("1234"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode("admin123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            //.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/home", "/", "/custom-login").permitAll()       // public
                .requestMatchers("/admin").hasRole("ADMIN") // only admin
                .requestMatchers("/user").hasAnyRole("USER", "ADMIN")   // Allow both
                .anyRequest().authenticated()               // All others need login
            )
            .formLogin(form -> form
                .loginPage("/custom-login")          // custom login page
                .loginProcessingUrl("/login") // same endpoint form submits to
                .successHandler(customSuccessHandler()) // redirect after successful login
                .failureUrl("/custom-login?error=true")
                .permitAll())  // use default login page
            .logout(logout -> logout
                .logoutUrl("/perform-logout")
                .logoutSuccessUrl("/logout-success")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()); // default logout
        
        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return new CustomAuthenticationSuccessHandler();
    }
}
