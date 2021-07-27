package net.enilink.platform.security.modules;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class RequesterUtil {
    private static CloseableHttpClient client;

    public static String retrieveAuthEndpoint(String openidIdentifier) throws IOException {
        String configUrl = openidIdentifier;
        if (!configUrl.startsWith("https://")){
            configUrl = "https://" + configUrl;
        }
        if (!configUrl.endsWith(".well-known/openid-configuration")){
            if(!configUrl.endsWith("/")) configUrl = configUrl + "/";
            configUrl = configUrl + ".well-known/openid-configuration";
        }
        if(client == null)
            client =  HttpClientBuilder.create().build();
        HttpGet req = new HttpGet(configUrl);
        HttpResponse response;

        System.out.println("config Url : "+ configUrl);
        response = client.execute(req);
        Map config = new ObjectMapper().readValue(response.getEntity().getContent(), Map.class);
        System.out.println("op configurations: "+config);
        return (String) config.get("authorization_endpoint");
    }

    public static URI sendAuthRequest(String authEndpoint, String codeChallange, String retTo) throws URISyntaxException, IOException {
        if(client == null)
            client =  HttpClientBuilder.create().build();
        URIBuilder uriBuilder = new URIBuilder(authEndpoint);
        uriBuilder.setParameter("response_type", "code").
                setParameter("redirect_uri",retTo).
                setParameter("scope", "openid profile offline_access").
                setParameter("client_id", "http://www.w3.org/ns/solid/terms#PublicOidcClient").
                setParameter("code_challenge_method","S256").
                setParameter("code_challenge", codeChallange );
        return uriBuilder.build();
//        HttpGet req = new HttpGet(uriBuilder.build());
//        CloseableHttpResponse resp = client.execute(req);
//        System.out.println("auth req response: "+ resp.getStatusLine().getStatusCode()+", "+resp.getStatusLine().getReasonPhrase() );
//       for (Header h :  resp.getAllHeaders()){
//           System.out.println(h.getName() +" = "+ h.getValue());
//       }
    }
}
