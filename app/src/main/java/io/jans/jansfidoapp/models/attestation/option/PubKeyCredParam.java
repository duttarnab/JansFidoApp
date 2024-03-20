package io.jans.jansfidoapp.models.attestation.option;

public class PubKeyCredParam {
    private String type;
    private long alg;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public long getAlg() {
        return alg;
    }

    public void setAlg(long alg) {
        this.alg = alg;
    }
}
