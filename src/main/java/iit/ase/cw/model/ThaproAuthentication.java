package iit.ase.cw.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import iit.ase.cw.platform.common.security.model.ThaproRole;
import iit.ase.cw.platform.common.security.model.ThaproUser;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.stream.Collectors;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ThaproAuthentication<U extends ThaproUser> implements Authentication {

    private String userName;
    private U thaproUser;
    @JsonIgnore
    private String userSecret;
    private boolean isAuthenticated;

    private GrantedAuthority apply(ThaproRole thaproRole) {
        return () -> thaproRole.getRole();
        //return thaproRole::getRole;
    }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.thaproUser.getRoles().stream().map(this::apply)
            .collect(Collectors.toList());
    }

    @Override
    @JsonIgnore
    public Object getCredentials() {
        return userSecret;
    }

    @Override
    @JsonIgnore
    public Object getDetails() {
        return null;
    }

    @Override
    @JsonIgnore
    public Object getPrincipal() {
        return thaproUser;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    @JsonIgnore
    public String getName() {
        return this.thaproUser.getUserId();
    }
}
