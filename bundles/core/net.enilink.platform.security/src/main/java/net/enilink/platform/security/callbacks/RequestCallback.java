package net.enilink.platform.security.callbacks;

import javax.security.auth.callback.Callback;
import javax.servlet.http.HttpServletRequest;

public class RequestCallback implements Callback {
	private HttpServletRequest request;

	public HttpServletRequest getRequest() {
		return request;
	}

	public void setRequest(HttpServletRequest request) {
		this.request = request;
	}
}
