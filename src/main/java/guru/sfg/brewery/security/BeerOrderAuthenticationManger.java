package guru.sfg.brewery.security;

import guru.sfg.brewery.domain.security.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Slf4j
@Component
public class BeerOrderAuthenticationManger {

    public boolean customerIdMatches(Authentication authentication, UUID customerId) {
        User authenticatiedUser = (User) authentication.getPrincipal();

        log.debug("Auth User Customer Id: " + authenticatiedUser.getCustomer().getId() + " Customer Id: " + customerId);

        return authenticatiedUser.getCustomer().getId().equals(customerId);
    }

}
