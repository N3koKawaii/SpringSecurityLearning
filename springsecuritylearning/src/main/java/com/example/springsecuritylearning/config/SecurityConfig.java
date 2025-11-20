package com.example.springsecuritylearning.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
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
import com.example.springsecuritylearning.service.MyUserDetailsService;

@EnableMethodSecurity   
@Configuration
public class SecurityConfig {
    private final MyUserDetailsService myUserDetailsService;

        public SecurityConfig(MyUserDetailsService myUserDetailsService) {
                this.myUserDetailsService = myUserDetailsService;
                    }

                        @Bean
                            public PasswordEncoder passwordEncoder(){
                                    return new BCryptPasswordEncoder();
                                        }

                                            @Bean
                                                public SecurityFilterChain filterChain(
                                                                        HttpSecurity http,
                                                                                                CustomAuthenticationEntryPoint authEntryPoint,
                                                                                                                        CustomAccessDeniedHandler deniedHandler) throws Exception{
                                                                                                                                http
                                                                                                                                            .csrf(csrf -> csrf.disable())
                                                                                                                                                        .authorizeHttpRequests(auth -> auth
                                                                                                                                                                        .requestMatchers("/").hasRole("GUEST")
                                                                                                                                                                                        .requestMatchers("/admin").hasRole("ADMIN")
                                                                                                                                                                                                        .requestMatchers("/user").hasRole("USER")
                                                                                                                                                                                                                        .anyRequest().authenticated()
                                                                                                                                                                                                                                    )
                                                                                                                                                                                                                                                .httpBasic(Customizer.withDefaults())
                                                                                                                                                                                                                                                            .exceptionHandling(ex -> ex
                                                                                                                                                                                                                                                                            .authenticationEntryPoint(authEntryPoint)  //401
                                                                                                                                                                                                                                                                                            .accessDeniedHandler(deniedHandler)       //403
                                                                                                                                                                                                                                                                                                        )
                                                                                                                                                                                                                                                                                                                    .sessionManagement(session -> session
                                                                                                                                                                                                                                                                                                                                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                                                                                                                                                                                                                                                                                                                                                )
                                                                                                                                                                                                                                                                                                                                                            .anonymous(anon -> anon.authorities(List.of(new SimpleGrantedAuthority("ROLE_GUEST"))));

                                                                                                                                                                                                                                                                                                                                                                    return http.build();
                                                                                                                                                                                                                                                                                                                                                                        }

                                                                                                                                                                                                                                                                                                                                                                            @Bean
                                                                                                                                                                                                                                                                                                                                                                                public RoleHierarchy roleHierarchy() {
                                                                                                                                                                                                                                                                                                                                                                                        return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER > ROLE_GUEST");
                                                                                                                                                                                                                                                                                                                                                                                                
                                                                                                                                                                                                                                                                                                                                                                                                    }

                                                                                                                                                                                                                                                                                                                                                                                                    }
                                                                                                                                                                                                                                                                                                                                                                                                    