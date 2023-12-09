package iit.ase.cw.service;

import iit.ase.cw.platform.common.security.model.AuthenticationRequest;
import iit.ase.cw.platform.common.security.model.ThaproUser;

public interface ThaproUserDetailsPopulateService {

     ThaproUser findByUsername(AuthenticationRequest username);
}
