package no.ovalle.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static no.ovalle.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //specifies that any request (i.e. all requests) must be authenticated.
        http
                // Require authorization for a request to any path...
                .authorizeRequests()
                // except those paths specified here:
                .antMatchers("/", "/index.html", "/css/*", "/js/*").permitAll()
                // While all requests to /api/** must have role == STUDENT
                .antMatchers("/api/**").hasRole(STUDENT.name())
                // Any other request to any other path...
                .anyRequest()
                // must be authenticated...
                .authenticated()
                .and()
                // using basic authentication.
                .httpBasic();
    }

    @Override
    @Bean
    //this is where we retrieve/add our users in the user_DB
    protected UserDetailsService userDetailsService() {
        // We create users with a UserDetails builder

        // STUDENT user
        UserDetails annaSmithUser = User
                .builder()
                .username("annasmith")
                // we must encode the password, so it's not clear text.
                // we use BCrypt, see PasswordConfig.
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name()) // ROLE_STUDENT, used by Spring Security to handle authorisation
                .build();

        // ADMIN user
        UserDetails lindaUser = User
                .builder()
                .username("linda")
                .password(passwordEncoder.encode("123"))
                .roles(ADMIN.name())
                .build();


        // make a RAM DB of our user(s)
        return new InMemoryUserDetailsManager(
                annaSmithUser, lindaUser
        );
    }
}
