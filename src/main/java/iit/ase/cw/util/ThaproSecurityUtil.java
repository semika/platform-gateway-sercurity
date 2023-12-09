package iit.ase.cw.util;

import iit.ase.cw.platform.common.security.exception.ThaproAuthenticationException;
import iit.ase.cw.platform.common.security.model.AuthenticationRequest;
import org.springframework.web.server.ServerWebExchange;

import java.util.Base64;
import java.util.List;

public final class ThaproSecurityUtil {

    public ThaproSecurityUtil() {}

    public static AuthenticationRequest extractUserCredentialFromBasicHeader(ServerWebExchange serverWebExchange,
                                                                             String headerName) {
        String basicAuthHeader = getBasicAuthHeader(serverWebExchange, headerName);
        String detailPhrase = basicAuthHeader.substring("Basic ".length());
        String decoded = new String(Base64.getDecoder().decode(detailPhrase));
        String[] props = decoded.split(":");
        return AuthenticationRequest.builder().username(props[0]).password(props[1]).build();
    }

    public static String getRequestHeader(ServerWebExchange serverWebExchange, String headerName) {
        List<String> authorizationHeaderList = serverWebExchange.getRequest().getHeaders().get(headerName);
        if (authorizationHeaderList == null || authorizationHeaderList.isEmpty()) {
            throw new ThaproAuthenticationException("Unable to find the header, " + headerName);
        }
        return authorizationHeaderList.get(0);
    }

    public static String getBasicAuthHeader(ServerWebExchange serverWebExchange, String headerName) {
        String basicAuthHeader = getRequestHeader(serverWebExchange,  headerName);
        if (basicAuthHeader.startsWith("Basic ")) {
            return basicAuthHeader;
        } else {
            throw new ThaproAuthenticationException("Unable to find the basic auth token, " + headerName);
        }
    }

    public static String getBearerAuthHeader(ServerWebExchange serverWebExchange, String headerName) {
        String bearerAuthHeader = getRequestHeader(serverWebExchange,  headerName);
        if (bearerAuthHeader.startsWith("Bearer ")) {
            return bearerAuthHeader.substring("Bearer ".length());
        } else {
            throw new ThaproAuthenticationException("Unable to find the bearer auth token, " + headerName);
        }
    }

}
