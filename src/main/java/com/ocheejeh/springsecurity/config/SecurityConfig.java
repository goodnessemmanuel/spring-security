package com.ocheejeh.springsecurity.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.Customizer.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Value("${jwt.public.key}")
    private RSAPublicKey pubKey;

    @Value("${jwt.private.key}")
    private RSAPrivateKey privKey;

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
               //.httpBasic(withDefaults());
               .csrf((csrf) -> csrf.ignoringRequestMatchers("/token"))
               .httpBasic(Customizer.withDefaults())
               .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
               .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .exceptionHandling((exceptions) -> exceptions
                       .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                       .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));
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

        LOG.info(">>>Creating an in-memory test user: {}", user.toString());
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(this.pubKey).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(this.pubKey).privateKey(this.privKey).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

}
