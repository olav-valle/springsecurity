package no.ovalle.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.concurrent.TimeUnit;

import static no.ovalle.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
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
                .csrf()
                // we disable csrf, since this service is a backend API for machines.
                // enable this if the service is browser based and user-facing,
                // by swapping around which of the next two lines is commented:
                .disable()
                //.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()

                // Require authorization for a request to any path...
                .authorizeRequests()

                // except those paths specified here:
                .antMatchers("/", "/index.html", "/css/*", "/js/*").permitAll()

                // While all requests to /api/** must have role == STUDENT
                .antMatchers("/api/**").hasRole(STUDENT.name())

                // These matchers are replaced by @PreAuth annotation at the method level
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())

                // Any other request to any other path...
                .anyRequest()

                // must be authenticated...
                .authenticated()

                // using form based authentication.
                .and()
                .formLogin()
                    .loginPage("/login").permitAll()
                    // and redirect to "/courses" upon successful login
                    .defaultSuccessUrl("/courses", true)
                    // set custom username and password field parameter names
                    // which must then be used in the login form as well
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                // Remember user login...
                .rememberMe()
                    // for 21 days.
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("somethingReallySecure...")
                    // we can set a custom remember-me parameter name
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/");
    }

    @Override
    @Bean
    //this is where we retrieve/add our users in the user_DB
    protected UserDetailsService userDetailsService() {
        // We create users with a UserDetails builder

        // Roles are defined in ApplicationUserRoles enum

        // STUDENT user
        UserDetails annaSmithUser = User
                .builder()
                .username("annasmith")
                // we must encode the password, so it's not clear text.
                // we use BCrypt, see PasswordConfig.
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) // ROLE_STUDENT, used by Spring Security to handle authorisation
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        // ADMIN user
        UserDetails lindaUser = User
                .builder()
                .username("linda")
                .password(passwordEncoder.encode("123"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        // ADMINTRAINEE user = read only
        UserDetails tomUser = User
                .builder()
                .username("tom")
                .password(passwordEncoder.encode("123"))
//                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();


        // make a RAM DB of our user(s)
        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
}
