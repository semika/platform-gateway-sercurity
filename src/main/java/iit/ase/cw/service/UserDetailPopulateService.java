package iit.ase.cw.service;

import iit.ase.cw.platform.common.security.model.AuthenticationRequest;
import iit.ase.cw.platform.common.security.model.ThaproUser;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;



public class UserDetailPopulateService implements ThaproUserDetailsPopulateService {
    @Override
    public ThaproUser findByUsername(String username) {

        ThaproUser thaproUser = new ThaproUser();
        thaproUser.setUserId("user");
        thaproUser.setOrganizationId(1000);

        return thaproUser;
    }
}
