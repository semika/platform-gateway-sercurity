/*
 * ====================================================================
 * Copyright  (c) : 2021 by Kaleris. All rights reserved.
 * ====================================================================
 *
 * The copyright to the computer software herein is the property of Kaleris
 * The software may be used and/or copied only
 * with the written permission of Kaleris or in accordance
 * with the terms and conditions stipulated in the agreement/contract
 * under which the software has been supplied.
 */

package iit.ase.cw.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import iit.ase.cw.authenticator.ThaproReactiveUserAuthenticator;
import iit.ase.cw.platform.common.context.model.ThaproApplicationContext;
import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.security.common.model.ThaproAuthentication;
import iit.ase.cw.security.common.util.ThaproJwtTokenHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
public class GatewaySecurityFilter implements WebFilter {

    private ThaproJwtTokenHandler jwtTokenHandler;

    private ThaproReactiveUserAuthenticator thaproReactiveUserAuthenticator;

    public GatewaySecurityFilter(ThaproJwtTokenHandler jwtTokenHandler,
                                 ThaproReactiveUserAuthenticator thaproReactiveUserAuthenticator) {
        this.jwtTokenHandler = jwtTokenHandler;
        this.thaproReactiveUserAuthenticator = thaproReactiveUserAuthenticator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange serverWebExchange, WebFilterChain chain) {

        Authentication authenticated = this.thaproReactiveUserAuthenticator.authenticate(serverWebExchange);

        try {
            String jwt = this.jwtTokenHandler.createToken((ThaproAuthentication) authenticated);
            serverWebExchange.getRequest().mutate().headers((httpHeaders -> {
                httpHeaders.add(ThaproSecurityConstant.Header.THAPRO_AUTHENTICATED_HEADER, jwt);
            }));
            return chain.filter(serverWebExchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authenticated));
        }  catch (JsonProcessingException e) {
            log.error("Unabled to set authorization header for downstream services", e);
            return serverWebExchange.getResponse()
                    .writeWith(Mono.error(new RuntimeException("Unabled to set authorization header for downstream services", e)));
        } finally {
            ThaproApplicationContext.clearContext();
        }
    }
}
