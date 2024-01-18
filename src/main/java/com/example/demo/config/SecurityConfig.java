
package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig  {
    private final JwtAuthorizationFilter authorizationFilter;


    private final MyUserDetailsService userDetailsService;

    public SecurityConfig(JwtAuthorizationFilter authorizationFilter, MyUserDetailsService userDetailsService) {
        this.authorizationFilter = authorizationFilter;
        this.userDetailsService = userDetailsService;
    }





   /* @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, UserDetailsService userDetailsService)

            throws Exception {
        http
                .authorizeHttpRequests(
                        req ->
                                req
                                .requestMatchers(new AntPathRequestMatcher( "/public/**", "/rest/auth")
                               ).permitAll()
                                .requestMatchers(new AntPathRequestMatcher("api/books/**")).hasAuthority("ADMIN")
                                .anyRequest().authenticated()
                )
//                .userDetailsService(userDetailsService)
                .headers(headers-> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
//                .formLogin(Customizer.withDefaults())
                .sessionManagement(sec-> sec.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class)
//                .loginPage("/login")
//                .permitAll()
//                .and()
//                .logout(Customizer.withDefaults())
        ;

        return http.build();
    }*/



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .authorizeRequests()
                .requestMatchers("/rest/auth/**").permitAll()
                .anyRequest().authenticated()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();
    }
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, NoOpPasswordEncoder passwordEncoder1)
            throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder1);
        return authenticationManagerBuilder.build();
    }

    @SuppressWarnings("deprecation")
    @Bean
    public NoOpPasswordEncoder passwordEncoder1() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

}



