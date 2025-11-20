package com.example.springsecuritylearning.config;

import java.util.List;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.example.springsecuritylearning.auth.CustomAccessDeniedHandler;
import com.example.springsecuritylearning.auth.CustomAuthenticationEntryPoint;
import com.example.springsecuritylearning.model.AppUser;
import com.example.springsecuritylearning.repository.UserRepository;
import com.example.springsecuritylearning.service.MyUserDetailsService;

@EnableMethodSecurity
@Configuration
public class SecurityConfig {
    private final MyUserDetailsService myUserDetailsService;

    public SecurityConfig(MyUserDetailsService myUserDetailsService) {
        this.myUserDetailsService = myUserDetailsService;
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
            AuthenticationManager authManager) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/","/h2/**").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/user").hasRole("USER")
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authEntryPoint) // 401
                        .accessDeniedHandler(deniedHandler) // 403
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .anonymous(anon -> anon.authorities(List.of(new SimpleGrantedAuthority("ROLE_GUEST"))))
                .authenticationManager(authManager)
                .headers(headers -> headers.frameOptions(frame -> frame.disable()));

        return http.build();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER > ROLE_GUEST");
    }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http, PasswordEncoder encoder, MyUserDetailsService userDetailsService) throws Exception{
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(encoder);

        return new ProviderManager(provider);
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
