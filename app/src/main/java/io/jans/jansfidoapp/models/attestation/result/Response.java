package io.jans.jansfidoapp.models.attestation.result;

public class Response {
    private String attestationObject;
    //private ClientDataJSON clientDataJSON;
    private String clientDataJSON;

    public String getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(String attestationObject) {
        this.attestationObject = attestationObject;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public void setClientDataJSON(String clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }
}
