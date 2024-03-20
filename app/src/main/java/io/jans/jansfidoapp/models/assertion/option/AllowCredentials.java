package io.jans.jansfidoapp.models.assertion.option;

import java.util.List;

public class AllowCredentials {
    private String id;
    private String type;
    private List<String> transports;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<String> getTransports() {
        return transports;
    }

    public void setTransports(List<String> transports) {
        this.transports = transports;
    }
}
