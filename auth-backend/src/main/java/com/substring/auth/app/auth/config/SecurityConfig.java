package com.substring.auth.app.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.auth.app.dtos.ApiError;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final org.springframework.security.web.authentication.AuthenticationSuccessHandler successHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers(AppConstants.AUTH_PUBLIC_URLS).permitAll()
                                .requestMatchers(AppConstants.AUTH_ADMIN_URLS)
                                .hasRole(AppConstants.ADMIN_ROLE)
                                .requestMatchers(AppConstants.AUTH_GUEST_URLS)
                                .hasRole(AppConstants.GUEST_ROLE)
                                .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 ->
                        oauth2.successHandler(successHandler)
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, e) -> {

                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setContentType("application/json");

                            String message = e.getMessage();
                            String error = (String) request.getAttribute("error");
                            if (error != null) {
                                message = error;
                            }

                            var apiError = ApiError.of(
                                    HttpStatus.UNAUTHORIZED.value(),
                                    "Unauthorized Access",
                                    message,
                                    request.getRequestURI(),
                                    true
                            );

                            response.getWriter().write(
                                    new ObjectMapper().writeValueAsString(apiError)
                            );
                        })
                        .accessDeniedHandler((request, response, e) -> {

                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setContentType("application/json");

                            var apiError = ApiError.of(
                                    HttpStatus.FORBIDDEN.value(),
                                    "Forbidden Access",
                                    e.getMessage(),
                                    request.getRequestURI(),
                                    true
                            );

                            response.getWriter().write(
                                    new ObjectMapper().writeValueAsString(apiError)
                            );
                        })
                )
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.front-end-url}") String corsUrls
    ) {

        String[] urls = corsUrls.trim().split(",");

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(urls));
        config.setAllowedMethods(
                List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD")
        );
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", config);

        return source;
    }
}