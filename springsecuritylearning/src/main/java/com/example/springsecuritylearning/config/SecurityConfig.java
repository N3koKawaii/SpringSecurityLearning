package com.example.springsecuritylearning.config;

import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.springsecuritylearning.auth.CustomAccessDeniedHandler;
import com.example.springsecuritylearning.auth.CustomAuthenticationEntryPoint;
import com.example.springsecuritylearning.model.AppUser;
import com.example.springsecuritylearning.repository.UserRepository;
import com.example.springsecuritylearning.service.TokenRevocationService;

import lombok.RequiredArgsConstructor;

@EnableMethodSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtUtil jwtUtil;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(UserDetailsService userDetailsService, TokenRevocationService revSvc) {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService, revSvc);
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository repo) {
        return username -> {
            AppUser user = repo.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            return new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    user.getPassword(),
                    user.getRoles().stream()
                            .map(role -> new SimpleGrantedAuthority(role))
                            .toList()
            );
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(
        AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            CustomAuthenticationEntryPoint authEntryPoint,
            CustomAccessDeniedHandler deniedHandler, 
            JwtAuthenticationFilter jwtAuthenticationFilter,
            AuthenticationManager authManager) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/","/h2/**").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/user").hasRole("USER")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authEntryPoint) // 401
                        .accessDeniedHandler(deniedHandler) // 403
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .anonymous(anon -> anon.authorities(List.of(new SimpleGrantedAuthority("ROLE_GUEST"))))
                .headers(headers -> headers.frameOptions(frame -> frame.disable())); // allow H2 console frames

        return http.build();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER > ROLE_GUEST");
    }

    @Bean
    public CommandLineRunner init(UserRepository repo, PasswordEncoder encoder){
        return args -> {
            AppUser admin = new AppUser();
            admin.setUsername("admin");
            admin.setPassword(encoder.encode("admin1"));
            admin.getRoles().add("ROLE_ADMIN");

            AppUser user = new AppUser();
            user.setUsername("user");
            user.setPassword(encoder.encode("user1"));
            user.getRoles().add("ROLE_USER");
            
            repo.saveAll(List.of(admin, user));
        };
    }

}
