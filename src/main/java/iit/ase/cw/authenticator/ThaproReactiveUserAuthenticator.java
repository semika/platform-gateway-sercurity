package iit.ase.cw.authenticator;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public interface ThaproReactiveUserAuthenticator {

    Authentication authenticate(ServerWebExchange serverWebExchange);

}
