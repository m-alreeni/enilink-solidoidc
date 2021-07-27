
package net.enilink.platform.security.modules;


import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.Set;

public class WebIdPrincipal  implements Principal, java.io.Serializable {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebIdPrincipal.class);
    private static final long serialVersionUID = -9108763403819614409L;

    private final String webid;
    private final DecodedJWT jwt;

    public WebIdPrincipal(final String token)  {
        this.jwt = JWT.decode(token);
        this.webid = getWebId();
        LOGGER.debug("Using webid: {}", webid);
    }

    public Claim getClaim(String name) {
        return jwt.getClaim(name);
    }

    public Set<String> getClaimNames() {
        return jwt.getClaims().keySet();
    }

    @Override
    public String getName() {
        return webid;
    }

     String getWebId()  {
        if (jwt.getClaims().keySet().contains("webid")) {
            return jwt.getClaim("webid").asString();
        }

        final String subject = jwt.getSubject();
        if (isUrl(subject)) {
            return subject;
        }

        final String issuer = jwt.getIssuer();
        if (isUrl(issuer)) {
            return concat(issuer, subject);
        }

        return null;
    }

    static String concat(final String issuer, final String subject) {
        if (subject != null) {
            if (issuer.endsWith("/")) {
                return issuer + subject;
            }
            return issuer + "/" + subject;
        }

        return null;
    }

    static boolean isUrl(final String url) {
        return url != null && (url.startsWith("http://") || url.startsWith("https://"));
    }
}

