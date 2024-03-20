package io.jans.jansfidoapp.models.attestation.option;

import java.util.List;

public class AttestationOptionResponse {
    private String attestation;
    private AuthenticatorSelection authenticatorSelection;
    private String challenge;
    private List<PubKeyCredParam> pubKeyCredParams;
    private RP rp;
    private User user;

    public AuthenticatorSelection getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public void setAuthenticatorSelection(AuthenticatorSelection authenticatorSelection) {
        this.authenticatorSelection = authenticatorSelection;
    }

    public String getAttestation() {
        return attestation;
    }

    public void setAttestation(String attestation) {
        this.attestation = attestation;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public List<PubKeyCredParam> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public void setPubKeyCredParams(List<PubKeyCredParam> pubKeyCredParams) {
        this.pubKeyCredParams = pubKeyCredParams;
    }

    public RP getRp() {
        return rp;
    }

    public void setRp(RP rp) {
        this.rp = rp;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
