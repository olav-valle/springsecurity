package no.ovalle.springsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //specifies that any request (i.e. all requests) must be authenticated.
        http
                // Require authorization for a request to any path...
                .authorizeRequests()
                // except those paths specified here...
                .antMatchers("/", "/index.html", "/css/*", "/js/*")
                .permitAll()
                // but all other requests...
                .anyRequest()
                // must be authenticated...
                .authenticated()
                .and()
                // using basic authentication.
                .httpBasic();

    }

}
