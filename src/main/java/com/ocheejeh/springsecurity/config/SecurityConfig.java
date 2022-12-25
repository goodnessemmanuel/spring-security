package com.ocheejeh.springsecurity.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
   private final Logger LOG = LoggerFactory.getLogger(SecurityConfig.class);


    /**
     * configuring http security
     * @param http
     * @return
     * @throws Exception
     * register a security filter chain
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
       LOG.info(">>Creating a Security filter chain bean for http security: {}", http);
       http.
               authorizeHttpRequests((authz) ->
                   authz
                           // Spring Security should completely ignore URLs /ignore starting with /resources/, /ignore/
                           .requestMatchers( "/resources/**", "/ignore", "/ignore/**").permitAll()
                           .anyRequest().authenticated()

               )
               .httpBasic(withDefaults());
      return http.build();
    }

    /**
     *  configuring urls to ignore
     * @return
     */
//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) -> web.ignoring()
//                // Spring Security should completely ignore URLs starting with /resources/
//                .requestMatchers("/resources/**", "/ignore");
//    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        LOG.info(">>>Creating an inmemory test user: {}", user.toString());
        return new InMemoryUserDetailsManager(user);
    }

}
