package io.jans.jansfidoapp.models.attestation.option;

public class AuthenticatorSelection {
    private String authenticatorAttachment;
    private boolean requireResidentKey;
    private String userVerification;
    private String residentKey;

    public String getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public void setAuthenticatorAttachment(String authenticatorAttachment) {
        this.authenticatorAttachment = authenticatorAttachment;
    }

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public void setRequireResidentKey(boolean requireResidentKey) {
        this.requireResidentKey = requireResidentKey;
    }

    public String getUserVerification() {
        return userVerification;
    }

    public void setUserVerification(String userVerification) {
        this.userVerification = userVerification;
    }

    public String getResidentKey() {
        return residentKey;
    }

    public void setResidentKey(String residentKey) {
        this.residentKey = residentKey;
    }
}
