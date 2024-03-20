package io.jans.jansfidoapp.models.assertion.option;

import java.util.List;

public class AssertionOptionResponse {
    private String challenge;
    private String user;
    private String userVerification;
    private String rpId;
    private String status;
    private String errorMessage;
    private List<AllowCredentials> allowCredentials;

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getUserVerification() {
        return userVerification;
    }

    public void setUserVerification(String userVerification) {
        this.userVerification = userVerification;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public List<AllowCredentials> getAllowCredentials() {
        return allowCredentials;
    }

    public void setAllowCredentials(List<AllowCredentials> allowCredentials) {
        this.allowCredentials = allowCredentials;
    }

    @Override
    public String toString() {
        return "AssertionOptionResponse{" +
                "challenge='" + challenge + '\'' +
                ", user='" + user + '\'' +
                ", userVerification='" + userVerification + '\'' +
                ", rpId='" + rpId + '\'' +
                ", status='" + status + '\'' +
                ", errorMessage='" + errorMessage + '\'' +
                ", allowCredentials=" + allowCredentials +
                '}';
    }
}
