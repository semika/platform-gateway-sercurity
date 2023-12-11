package iit.ase.cw.config;

import iit.ase.cw.authenticator.ThaproReactiveBasicUserAuthenticator;
import iit.ase.cw.authenticator.ThaproReactiveJWTUserAuthenticator;
import iit.ase.cw.authenticator.ThaproReactiveUserAuthenticator;
import iit.ase.cw.platform.common.security.constant.ThaproSecurityConstant;
import iit.ase.cw.security.common.util.ThaproJwtTokenHandler;
import iit.ase.cw.service.ThaproUserDetailsPopulateService;
import iit.ase.cw.service.UserDetailPopulateService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_CLIENT_ENABLED, havingValue = "true")
public class GatewaySecurityConfiguration {

    private ThaproUserDetailsPopulateService thaproUserDetailsPopulateService;

    public GatewaySecurityConfiguration(ThaproUserDetailsPopulateService thaproUserDetailsPopulateService) {
        this.thaproUserDetailsPopulateService = thaproUserDetailsPopulateService;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
                                                            GatewaySecurityFilter gatewaySecurityFilter) throws Exception {
        http.authorizeExchange(exchanges -> exchanges
                        .anyExchange().authenticated())
                .csrf(csrfSpec -> csrfSpec.disable()) //Will appy CSRF filter
                .httpBasic(httpBasicSpec -> httpBasicSpec.disable())
                .formLogin(formLoginSpec -> formLoginSpec.disable())
                .addFilterBefore(gatewaySecurityFilter, SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }

    @Bean
    public GatewaySecurityFilter gatewaySecurityFilter(ThaproReactiveUserAuthenticator thaproReactiveUserAuthenticator,
                                                       ThaproJwtTokenHandler thaproJwtTokenHandler) {
        return new GatewaySecurityFilter(thaproJwtTokenHandler, thaproReactiveUserAuthenticator);
    }

    @Bean
    @ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_CLIENT_BASIC_AUTH_ENABLED, havingValue = "true")
    public ThaproReactiveUserAuthenticator thaproReactiveBasicUserAuthenticator(
            ThaproUserDetailsPopulateService thaproUserDetailsPopulateService) {
        return new ThaproReactiveBasicUserAuthenticator(thaproUserDetailsPopulateService, jwtUtil());
    }

    @Bean
    @ConditionalOnProperty(value = ThaproSecurityConstant.Security.SECURITY_CLIENT_JWT_AUTH_ENABLED, havingValue = "true")
    public ThaproReactiveUserAuthenticator thaproReactiveJWTUserAuthenticator(
            ThaproUserDetailsPopulateService thaproUserDetailsPopulateService, ThaproJwtTokenHandler jwtUtil) {
        return new ThaproReactiveJWTUserAuthenticator(thaproUserDetailsPopulateService, jwtUtil);
    }

    @Bean
    public ThaproJwtTokenHandler jwtUtil() {
        return new ThaproJwtTokenHandler();
    }

    @ConditionalOnMissingBean
    @Bean
    public UserDetailPopulateService userDetailPopulateService() {
        return new UserDetailPopulateService();
    }
}
