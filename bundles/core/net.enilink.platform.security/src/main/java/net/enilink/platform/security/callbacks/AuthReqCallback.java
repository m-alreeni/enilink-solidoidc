package net.enilink.platform.security.callbacks;

import javax.security.auth.callback.Callback;

public class AuthReqCallback implements Callback {
    private String uri;

    public AuthReqCallback(String authUri) {
        this.uri = authUri;
    }

    public void  setUri(String uri){
        this.uri = uri;
    }

    public String getUri(){
        return this.uri;
    }
}
