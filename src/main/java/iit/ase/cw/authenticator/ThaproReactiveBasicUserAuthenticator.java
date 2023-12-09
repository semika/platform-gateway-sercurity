package iit.ase.cw.authenticator;

import com.fasterxml.jackson.core.JsonProcessingException;
import iit.ase.cw.model.ThaproAuthentication;
import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.platform.common.security.model.AuthenticationRequest;
import iit.ase.cw.platform.common.security.model.ThaproUser;
import iit.ase.cw.service.ThaproUserDetailsPopulateService;
import iit.ase.cw.util.ThaproJwtTokenHandler;
import iit.ase.cw.util.ThaproSecurityUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;

public class ThaproReactiveBasicUserAuthenticator implements ThaproReactiveUserAuthenticator {

    private ThaproUserDetailsPopulateService thaproUserDetailsPopulateService;
    private ThaproJwtTokenHandler jwtUtil;

    public ThaproReactiveBasicUserAuthenticator (ThaproUserDetailsPopulateService thaproUserDetailsPopulateService,
                                                 ThaproJwtTokenHandler jwtUtil) {
        this.thaproUserDetailsPopulateService = thaproUserDetailsPopulateService;
        this.jwtUtil = jwtUtil;
    }
    @Override
    public Authentication authenticate(ServerWebExchange serverWebExchange) {
        // Get authorization header and validate
        try {
            Authentication authentication = handleAuthentication(serverWebExchange);
            return authentication;
        } catch (Exception exception) {
            exception.printStackTrace(); //TODO replace with proper loggin mechenisum
            return null; //Not security context is created. 401 will be returned
        }
    }

    private Authentication handleAuthentication(ServerWebExchange serverWebExchange) {

        // Get authorization header and validate
        String authorization = ThaproSecurityUtil.getBasicAuthHeader(serverWebExchange, HttpHeaders.AUTHORIZATION);
        if (authorization == null) {
            throw new RuntimeException("Authentication error. Authorization header missing");
        }

        //Extract login credentials
        AuthenticationRequest authenticationRequest = ThaproSecurityUtil.extractUserCredentialFromBasicHeader(
            serverWebExchange, HttpHeaders.AUTHORIZATION);
        Authentication authentication = new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
            authenticationRequest.getPassword());

        //Load the user and role from the database.
        ThaproUser thaproUser = thaproUserDetailsPopulateService.findByUsername(authenticationRequest);
        if (thaproUser == null) {
            throw new RuntimeException("Authentication error. Unable to find the user");
        }

        //validate password, check the user provided password against the database one.
        Boolean isValidPassword = validatePassword(authentication.getCredentials().toString(), thaproUser.getPassword());
        if (!isValidPassword) {
            throw new RuntimeException("Authentication error. Invalid login credentials");
        }

        ThaproAuthentication authenticated = ThaproAuthentication.builder().
                thaproUser(thaproUser)
                .isAuthenticated(true)
                .userSecret(thaproUser.getPassword()).build();

        //set JWT header for downstream services
        try {
            //set jwt for downstream services.
            String jwt = jwtUtil.createToken(authenticated);
            serverWebExchange.getRequest().mutate().headers((httpHeaders -> {
                httpHeaders.add(ThaproSecurityConstant.Header.THAPRO_AUTHENTICATED_HEADER, jwt);
            }));
        } catch (JsonProcessingException e) {
            new RuntimeException("Authentication error. Unable to parse user details to JSON", e);
        }

        return authenticated;
    }

    private Boolean validatePassword(String requestPassword, String dbPassword) {
        String formattedPW = dbPassword.replace("{noop}", "");
        return requestPassword.equals(formattedPW);
    }
}
