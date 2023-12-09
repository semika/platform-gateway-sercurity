package iit.ase.cw.exception;

import org.springframework.http.HttpStatus;

public class ThaproUnAuthorizedException extends RuntimeException {
    private String messageKey;
    private String module;
    private String user;
    private String message;
    private HttpStatus httpStatus = HttpStatus.UNAUTHORIZED;

    public ThaproUnAuthorizedException(String module, String message, String user) {
        //super(KalerisSecurityConstant.MessageKey.UN_AUTHORIZED_USER);
        //this.messageKey = KalerisSecurityConstant.MessageKey.UN_AUTHORIZED_USER;
        this.module = module;
        this.user = user;
        this.message = message;
    }

    public static ThaproUnAuthorizedException of(String module, String message, String user) {
        return new ThaproUnAuthorizedException(module, message, user);
    }

    public static ThaproUnAuthorizedException of() {
        return new ThaproUnAuthorizedException("", "", "");
    }

}
