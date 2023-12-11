package iit.ase.cw.service;

import iit.ase.cw.platform.common.security.model.ThaproUser;

public class UserDetailPopulateService implements ThaproUserDetailsPopulateService {
    @Override
    public ThaproUser findByUsername(String username) {

        ThaproUser thaproUser = new ThaproUser();
        thaproUser.setUserId("user");
        thaproUser.setOrganizationId(1000);

        return thaproUser;
    }
}
