package iit.ase.cw.authenticator;

import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;

public interface ThaproReactiveUserAuthenticator {

    Authentication authenticate(ServerWebExchange serverWebExchange);

}
