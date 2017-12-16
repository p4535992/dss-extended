package eu.europa.esig.dss.client.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.Callable;

import javax.net.ssl.HttpsURLConnection;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.client.http.MaxSizeInputStream;
import eu.europa.esig.dss.client.http.ProxyNativeHTTPDataLoader.HttpMethod;
import eu.europa.esig.dss.client.http.ProxyNativeHTTPDataLoader.HttpProtocol;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.utils.Utils;
/**
 * @deprecated use instead {@link CommonsDataLoader}
 */
public class ProxyNativeDataLoaderCall implements Callable<byte[]> {

	private static final String ERROR_MESSAGE = "An error occured while reading from url '%s' : %s";
	
	private String url;
	private byte[] content;
	private long maxInputSize;
	private Proxy proxy;
	private HttpMethod httpMethod;
	private HttpProtocol protocol;

	private boolean useCaches;

	public ProxyNativeDataLoaderCall(String url, byte[] content, boolean useCaches, long maxInputSize,Proxy proxy,HttpMethod httpMethod,HttpProtocol protocol) {
		super();
		this.url = url;
		this.content = content;
		this.useCaches = useCaches;
		this.maxInputSize = maxInputSize;
		this.proxy = proxy;
		this.httpMethod = httpMethod;
		this.protocol = protocol;
	}
	
	public byte[] call() {
		OutputStream out = null;
		InputStream inputStream = null;
		byte[] result = null;
		try {
			URLConnection connection = createConnection();
			if(protocol.equals(HttpProtocol.HTTP)){			
				((HttpURLConnection)connection).setRequestMethod(httpMethod.name());
			}else if(protocol.equals(HttpProtocol.HTTPS)){
				((HttpsURLConnection)connection).setRequestMethod(httpMethod.name());
			}
			connection.setUseCaches(useCaches);
			connection.setDoInput(true);			
			if (content != null) {
				connection.setDoOutput(true);
				out = connection.getOutputStream();
				Utils.write(content, out);
			}
			inputStream = connection.getInputStream();
			result = Utils.toByteArray(maxInputSize > 0? new MaxSizeInputStream(inputStream, maxInputSize, url): inputStream);
		} catch (IOException e) {
			throw new DSSException(String.format(ERROR_MESSAGE, url, e.getMessage()), e);
		} finally {
			Utils.closeQuietly(out);
			Utils.closeQuietly(inputStream);
		}
		return result;
	}

	protected URLConnection createConnection() throws MalformedURLException, IOException {
		//return (HttpsURLConnection)new URL(url).openConnection(proxy);
		return new URL(url).openConnection(proxy);
	}

	public String getUrl() {
		return url;
	}

	public byte[] getContent() {
		return content;
	}

	public long getMaxInputSize() {
		return maxInputSize;
	}

	public boolean isUseCaches() {
		return useCaches;
	}
}