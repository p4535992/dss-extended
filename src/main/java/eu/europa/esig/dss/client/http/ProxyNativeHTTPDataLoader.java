package eu.europa.esig.dss.client.http;

import java.net.Authenticator;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.client.http.TspHTTPDataLoader.HttpMethod;
import eu.europa.esig.dss.client.http.TspHTTPDataLoader.HttpProtocol;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;

/**
 * Implementation of native java DataLoader using the java.net.URL class.
 * with the implementation of a proxy.
 * @deprecated use instead {@link CommonsDataLoader}
 */
public class ProxyNativeHTTPDataLoader implements DataLoader {

	public enum HttpMethod {
		GET, POST
	}
	
	public enum HttpProtocol {
		HTTP, HTTPS
	}
	
	public ProxyNativeHTTPDataLoader(Proxy proxy){
		this.proxy = proxy;	
	}
	
	public ProxyNativeHTTPDataLoader(Proxy proxy,final String usernameProxy,final String passwordProxy) throws NumberFormatException, UnknownHostException{
		this.proxy = proxy;
		if(usernameProxy!=null && !usernameProxy.isEmpty() && passwordProxy!=null && !passwordProxy.isEmpty()){
			Authenticator authenticator = new Authenticator() {
			    public PasswordAuthentication getPasswordAuthentication() {
			        return (new PasswordAuthentication(usernameProxy,passwordProxy.toCharArray()));
			    }
			};
			Authenticator.setDefault(authenticator);
		}		
	}
	
	public ProxyNativeHTTPDataLoader(String proxyHost,String proxyPort,final String usernameProxy,final String passwordProxy,Type type) throws NumberFormatException, UnknownHostException{
		SocketAddress socketAddress = new InetSocketAddress(InetAddress.getByName(proxyHost), Integer.parseInt(proxyPort));
		this.proxy = new Proxy(type, socketAddress);
		if(usernameProxy!=null && !usernameProxy.isEmpty() && passwordProxy!=null && !passwordProxy.isEmpty()){
			Authenticator authenticator = new Authenticator() {
			    public PasswordAuthentication getPasswordAuthentication() {
			        return (new PasswordAuthentication(usernameProxy,passwordProxy.toCharArray()));
			    }
			};
			Authenticator.setDefault(authenticator);
		}		
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyNativeHTTPDataLoader.class);

	private long maxInputSize;

	/**
	 * Timeout of the full request processing time (send and retrieve data).
	 */
	private long timeout = 0;
	private Proxy proxy;

	protected byte[] request(String url, HttpMethod method, byte[] content, boolean refresh, HttpProtocol protocol) {
		ProxyNativeDataLoaderCall task = new ProxyNativeDataLoaderCall(url, content, refresh, maxInputSize,proxy,method,protocol);

		ExecutorService executorService = Executors.newSingleThreadExecutor();
		try {
			Future<byte[]> result = executorService.submit(task);
			return timeout > 0 ? result.get(timeout, TimeUnit.MILLISECONDS) : result.get();
		} catch (InterruptedException | ExecutionException | TimeoutException e) {
			throw new DSSException(e);
		} finally {
			executorService.shutdown();
		}

	}

	@Override
	public DataAndUrl get(List<String> urlStrings) {
		for (final String urlString : urlStrings) {
			try {
				final byte[] bytes = get(urlString);
				if (bytes != null) {
					return new DataAndUrl(bytes, urlString);
				}
			} catch (Exception e) {
				LOGGER.warn("Impossible to obtain data using {}", urlString, e);
			}
		}
		throw new DSSException(String.format("Impossible to obtain data using with given urls %s", urlStrings));
	}

	@Override
	public byte[] get(String url) {
		return get(url, false);
	}

	@Override
	public byte[] get(String url, boolean refresh) {
		return request(url, HttpMethod.GET, null, !refresh,HttpProtocol.HTTP);
	}

	@Override
	public byte[] post(String url, byte[] content) {
		return request(url, HttpMethod.POST, content, false,HttpProtocol.HTTP);
	}

	@Override
	public void setContentType(String contentType) {
		throw new DSSException("Not implemented");
	}

	public long getMaxInputSize() {
		return maxInputSize;
	}

	public void setMaxInputSize(long maxInputSize) {
		this.maxInputSize = maxInputSize;
	}

	public long getTimeout() {
		return timeout;
	}

	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}
	
	public byte[] get(String url, boolean refres,HttpProtocol protocol) {
		return request(url, HttpMethod.GET, null, !refres, protocol);
	}

	public byte[] post(String url, byte[] content,HttpProtocol protocol) {
		return request(url, HttpMethod.POST, content, false, protocol);
	}
}