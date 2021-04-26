package no.ovalle.springsecurity.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserService implements UserDetailsService {

    private final ApplicationUserDao applicationUserDAO;

// The @Qualifier("fake") annotation specifies exactly which @Repository class that implements ApplicationUserDao should be used,
// e.g., the one annotated @Repository("fake").
// We can use this when we have many implementations that we switch between.
    @Autowired
    public ApplicationUserService(@Qualifier("fake") ApplicationUserDao applicationUserDAO) {
        this.applicationUserDAO = applicationUserDAO;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return applicationUserDAO
                .selectApplicationUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User with name " + username + " not found."));
    }

}
