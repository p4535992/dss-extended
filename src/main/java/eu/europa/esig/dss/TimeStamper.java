package eu.europa.esig.dss;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import javax.print.attribute.standard.ReferenceUriSchemesSupported;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.anssi.ANSSIObjectIdentifiers;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.client.NonceSource;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.http.proxy.ProxyProperties;
import eu.europa.esig.dss.tsl.PolicyIdCondition;

/**
 * A utility class to help to masnage the creation of the TSPSoource of DSS
 * based on the project https://github.com/vakho10/Java-TSA-TimeStamper
 */
public abstract class TimeStamper
{
    public abstract URL getTsaUrl();
    
    public abstract int getTsaPort();
    
    public abstract String getTsaUsername();
    
    public abstract String getTsaPassword();
    
    public abstract String getTsaScheme();
    
    public abstract ASN1ObjectIdentifier getPolicyOid();
    
    public abstract DigestAlgorithm getDigestAlgorithm();
    
    public abstract ASN1ObjectIdentifier getTspaAlgorithm();

    public abstract Proxy getProxy();
    
    public abstract ProxyConfig getProxyConfig();

    public abstract byte[] getData();

    public abstract String getRequestMethod();

    public abstract Object[] getMessageDigest();
    
    public abstract NonceSource getNonceSource();
    
    public abstract String getKeyStorePath();
    public abstract String getKeyStoreType();
    public abstract String getKeyStorePassword();
    
    public abstract String getTrustStorePath();
    public abstract String getTrustStoreType();
    public abstract String getTrustStorePassword();
    
    //Generate method
    
    public abstract TimestampDataLoader timestampDataLoader();

    public abstract TimeStampResponse timestamp() throws Exception;

    public abstract TimeStampResponse timestamp(byte[] data) throws IOException,TSPException;

    //Re-set method avoid to rebuild the entire object
    
    public abstract void setProxy(String address, int port);
    public abstract void setProxy(String address, int port, boolean isHttps);
    public abstract void setProxy(String address, int port,String username,String password);
    public abstract void setProxy(String address, int port,String username,String password, boolean isHttps);
    public abstract void setProxy(String address, int port, final String username, final String password,String excludedHosts,boolean isHttps);
    
    public abstract void setKeyStore(String keyStorePath, String KeyStoreType,String KeyStorePassword);
    public abstract void setTrustStore(String trustStorePath, String trustStoreType,String trustStorePassword);
    
    public static class Builder
    {
        private ConcreteTimeStamper concreteTimeStamper;

        public Builder()
        {
            concreteTimeStamper = new ConcreteTimeStamper();
        }

        public Builder setRequestMethod(String requestMethod)
        {
            concreteTimeStamper.requestMethod = requestMethod;
            return this;
        }

        public Builder setTsaUrl(String url) throws MalformedURLException
        {
            concreteTimeStamper.tsaUrl = new URL(url);
            return this;
        }
        
        public Builder setTsaPort(int port) throws MalformedURLException
        {
            concreteTimeStamper.tsaPort = port;
            return this;
        }
        
        public Builder setTsaUsername(String username) throws MalformedURLException
        {
            concreteTimeStamper.tsaUsername = username;
            return this;
        }
        
        public Builder setTsaPassword(String password) throws MalformedURLException
        {
            concreteTimeStamper.tsaPassword = password;
            return this;
        }
        
        public Builder setTsaScheme(String tsaScheme) throws IOException
        {
        	String scheme =  tsaScheme.toLowerCase();
        	//support only http and https
        	if(scheme.equals("http") || scheme.equals("https")){
        		concreteTimeStamper.tsaScheme = scheme;
        	}else{
        		throw new IOException("The scheme " + tsaScheme + " is not supported! only HTTP and HTTPS are supported for now ");
        	}
            return this;
        }

        public Builder setProxy(String address, int port)
        {
            return setProxy(address, port, null, null,null,false);
        }
        
        public Builder setProxy(String address, int port, boolean isHttps)
        {
            return setProxy(address, port, null, null,null,isHttps);
        }
        
        public Builder setProxy(String address, int port,String username,String password)
        {
            return setProxy(address, port, null, null,null,false);
        }
        
        public Builder setProxy(String address, int port,String username,String password, boolean isHttps)
        {
            return setProxy(address, port, null, null,null,isHttps);
        }
        
        public Builder setProxy(String address, int port, final String username, final String password,String excludedHosts,boolean isHttps)
        {
            concreteTimeStamper.proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(address, port));
            if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password))
            {
                // Set default authentication
                Authenticator.setDefault(new Authenticator()
                {
                    @Override
                    public PasswordAuthentication getPasswordAuthentication()
                    {
                        return new PasswordAuthentication(username, password.toCharArray());
                    }
                });
            }
            ProxyProperties proxyProperties = new ProxyProperties();
            proxyProperties.setHost(address);
            proxyProperties.setPort(port);
            if(username != null && !username.isEmpty() && password!=null && !password.isEmpty()){
	            proxyProperties.setPassword(password);
	            proxyProperties.setUser(username);
            }
            if(excludedHosts!=null && !excludedHosts.isEmpty()){
            	proxyProperties.setExcludedHosts(excludedHosts);
            }
            ProxyConfig proxyConfig = new ProxyConfig();
            if(isHttps){
            	proxyConfig.setHttpsProperties(proxyProperties);
            }else{
            	proxyConfig.setHttpProperties(proxyProperties);
            }
            concreteTimeStamper.proxyConfig = proxyConfig;
            return this;
        }

        public Builder setData(byte[] data)
        {
            concreteTimeStamper.data = data;
            return this;
        }

        @Deprecated
        public Builder setMessageDigest(String algorithm, ASN1ObjectIdentifier digestAlgAsn1) throws NoSuchAlgorithmException
        {
            concreteTimeStamper.messageDigest = MessageDigest.getInstance(algorithm);
            //concreteTimeStamper.digestAlgAsn1 = digestAlgAsn1;
            concreteTimeStamper.tspaAlgorithm= digestAlgAsn1;
            return this;
        }
        
        
        public Builder setPolicyOid(String policyOid) throws NoSuchAlgorithmException, IOException
        {
        	concreteTimeStamper.policyOid = new ASN1ObjectIdentifier(policyOid);
        	return this;
        }
        
        public Builder setNonCeSource(NonceSource nonceSource) throws NoSuchAlgorithmException, IOException
        {
        	concreteTimeStamper.nonCeSource = nonceSource;
        	return this;
        }
        
        public Builder setMessageDigest(DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException, IOException
        {
        	ASN1ObjectIdentifier tspaAlgorithm = new ASN1ObjectIdentifier(digestAlgorithm.getOid().toString());
            concreteTimeStamper.messageDigest = MessageDigest.getInstance(digestAlgorithm.getJavaName());
            //concreteTimeStamper.digestAlgAsn1 = tspaAlgorithm;
            concreteTimeStamper.digestAlgorithm = digestAlgorithm;
            
            if(!TSPAlgorithms.ALLOWED.contains(tspaAlgorithm)){
            	throw new IOException("The TSPAlghoritms OID : " + digestAlgorithm.getOid().toString() + " is not on the list of supported oid of bouncycastle");
            }
            if(tspaAlgorithm.equals(TSPAlgorithms.SHA256))concreteTimeStamper.tspaAlgorithm=TSPAlgorithms.SHA256;
            else if(tspaAlgorithm.equals(TSPAlgorithms.SHA1))concreteTimeStamper.tspaAlgorithm=TSPAlgorithms.SHA1;
            
            
            if(concreteTimeStamper.tspaAlgorithm==null){
            	throw new IOException("The TSPAlghoritms OID : " + digestAlgorithm.getOid().toString() + " has not match on the list of supported oid of bouncycastle");
            }
            
            if(concreteTimeStamper.policyOid == null){
            	concreteTimeStamper.policyOid=tspaAlgorithm;
            }
            return this;
        }
        

		public void setKeyStore(String keyStorePath, String keyStoreType, String keyStorePassword) {
			concreteTimeStamper.keyStorePath=keyStorePath;
			concreteTimeStamper.keyStoreType=keyStoreType;
			concreteTimeStamper.keyStorePassword=keyStorePassword;				
		}


		public void setTrustStore(String trustStorePath, String trustStoreType, String trustStorePassword) {
			concreteTimeStamper.trustStorePath=trustStorePath;
			concreteTimeStamper.trustStoreType=trustStoreType;
			concreteTimeStamper.trustStorePassword=trustStorePassword;					
		}
	

        public TimeStamper build() throws CloneNotSupportedException
        {
            return (TimeStamper) concreteTimeStamper.clone();
        }

        private static class ConcreteTimeStamper extends TimeStamper implements Cloneable
        {
			public String tsaPassword;
			public String tsaUsername;
			private URL tsaUrl;
			private int tsaPort = 80;
            private Proxy proxy;
            private byte[] data;
            private String requestMethod;
            private MessageDigest messageDigest;
            //private ASN1ObjectIdentifier digestAlgAsn1;
            private ASN1ObjectIdentifier policyOid;
            private DigestAlgorithm digestAlgorithm;
            private ASN1ObjectIdentifier tspaAlgorithm;
            private NonceSource nonCeSource; 
            private ProxyConfig proxyConfig;
            private String tsaScheme = "http";
            
            private String keyStorePath;
            private String keyStoreType;
            private String keyStorePassword;

            private String trustStorePath;
            private String trustStoreType;
            private String trustStorePassword;
            
            @Override
            public URL getTsaUrl()
            {
                return tsaUrl;
            }
            
            @Override
            public int getTsaPort()
            {
                return tsaPort;
            }
            
            
            @Override
            public String getTsaUsername()
            {
                return tsaUsername;
            }
            
            @Override
            public String getTsaPassword()
            {
                return tsaPassword;
            }
            
            @Override
            public String getTsaScheme()
            {
                return tsaScheme;
            }

            @Override
            public Proxy getProxy()
            {
                return proxy;
            }
            
			@Override
			public ProxyConfig getProxyConfig() {				
				return proxyConfig;
			}	

            @Override
            public byte[] getData()
            {
                return data;
            }

            @Override
            public String getRequestMethod()
            {
                return requestMethod;
            }

            @Override
            public Object[] getMessageDigest()
            {
            	return new Object[] { messageDigest, tspaAlgorithm };
                //return new Object[] { messageDigest, digestAlgAsn1 };
            }
            
			@Override
			public ASN1ObjectIdentifier getPolicyOid() {				
				return policyOid;
			}
			
			@Override
			public DigestAlgorithm getDigestAlgorithm() {				
				return digestAlgorithm;
			}

			@Override
			public ASN1ObjectIdentifier getTspaAlgorithm() {			
				return tspaAlgorithm;
			}
			
			@Override
			public NonceSource getNonceSource() {
				return nonCeSource;
			}
			
			@Override
			public String getKeyStorePath() {
				return this.keyStorePath;
			}

			@Override
			public String getKeyStoreType() {
				return keyStoreType;
			}

			@Override
			public String getKeyStorePassword() {
				return keyStorePassword;
			}

			@Override
			public String getTrustStorePath() {
				return trustStorePath;
			}

			@Override
			public String getTrustStoreType() {
				return trustStoreType;
			}

			@Override
			public String getTrustStorePassword() {
				return trustStorePassword;
			}
			
			@Override
			public TimestampDataLoader timestampDataLoader(){
				//Start prepare tspdataloader
				TimestampDataLoader tspDataLoader =  new TimestampDataLoader();//Mange request to TSP server with a proxy		
				if(proxyConfig != null){
					tspDataLoader.setProxyConfig(proxyConfig);
				}
				if(tsaUsername!= null && !tsaUsername.isEmpty() &&
						tsaPassword!= null && !tsaPassword.isEmpty()){
					tspDataLoader.addAuthentication(tsaUrl.toString(), tsaPort, tsaScheme, tsaUsername,tsaPassword);
				}

				return tspDataLoader;
			}
						
			@Override
            public TimeStampResponse timestamp() throws IOException, TSPException
            {
                if (data == null || data.length == 0)
                {
                    throw new IllegalArgumentException("The data mustn't be empty!");
                }

                // Generate timestamp request object
                TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
                OutputStream out = null;
                tsqGenerator.setCertReq(true);

                // Calculate data digest
                messageDigest.update(data);
                byte[] digest = messageDigest.digest();

                //TimeStampRequest request = tsqGenerator.generate(digestAlgAsn1, digest);
                TimeStampRequest request = tsqGenerator.generate(tspaAlgorithm, digest);
                byte[] requestBytes = request.getEncoded();

                HttpURLConnection con = (HttpURLConnection) tsaUrl.openConnection(proxy);
                con.setDoOutput(true);
                con.setDoInput(true);
                con.setRequestMethod(requestMethod);
                con.setRequestProperty("Content-type", "application/timestamp-query");
                con.setRequestProperty("Content-length", String.valueOf(requestBytes.length));
                out = con.getOutputStream();
                out.write(requestBytes);
                out.flush();

                if (con.getResponseCode() != HttpURLConnection.HTTP_OK)
                {
                    throw new IOException("Received HTTP error: " + con.getResponseCode() + " - " + con.getResponseMessage());
                }
                InputStream in = con.getInputStream();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead = 0;
                while ((bytesRead = in.read(buffer, 0, buffer.length)) >= 0)
                {
                    baos.write(buffer, 0, bytesRead);
                }
                byte[] respBytes = baos.toByteArray();

                TimeStampResponse resp = new TimeStampResponse(respBytes);
                resp.validate(request);
                return resp;
            }

            @Override
            public TimeStampResponse timestamp(byte[] data) throws IOException, TSPException
            {
                this.data = data;
                return timestamp();
            }
            
            //METHOD to force the re-settings
            @Override
            public void setProxy(String address, int port)
            {
                setProxy(address, port, null, null,null,false);
            }
            @Override
            public void setProxy(String address, int port, boolean isHttps)
            {
                setProxy(address, port, null, null,null,isHttps);
            }
            @Override
            public void setProxy(String address, int port,String username,String password)
            {
                setProxy(address, port, null, null,null,false);
            }
            @Override
            public void setProxy(String address, int port,String username,String password, boolean isHttps)
            {
                setProxy(address, port, null, null,null,isHttps);
            }
            
            @Override
            public void setProxy(String address, int port, final String username, final String password,String excludedHosts,boolean isHttps)
            {
                this.proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(address, port));
                if (StringUtils.isNotEmpty(username) && StringUtils.isNotEmpty(password))
                {
                    // Set default authentication
                    Authenticator.setDefault(new Authenticator()
                    {
                        @Override
                        public PasswordAuthentication getPasswordAuthentication()
                        {
                            return new PasswordAuthentication(username, password.toCharArray());
                        }
                    });
                }
                ProxyProperties proxyProperties = new ProxyProperties();
                proxyProperties.setHost(address);
                proxyProperties.setPort(port);
                if(username != null && !username.isEmpty() && password!=null && !password.isEmpty()){
    	            proxyProperties.setPassword(password);
    	            proxyProperties.setUser(username);
                }
                if(excludedHosts!=null && !excludedHosts.isEmpty()){
                	proxyProperties.setExcludedHosts(excludedHosts);
                }
                ProxyConfig proxyConfig = new ProxyConfig();
                if(isHttps){
                	proxyConfig.setHttpsProperties(proxyProperties);
                }else{
                	proxyConfig.setHttpProperties(proxyProperties);
                }
                this.proxyConfig = proxyConfig;               
            }
            
            @Override
			public void setKeyStore(String keyStorePath, String keyStoreType, String keyStorePassword) {
				this.keyStorePath=keyStorePath;
				this.keyStoreType=keyStoreType;
				this.keyStorePassword=keyStorePassword;				
			}

			@Override
			public void setTrustStore(String trustStorePath, String trustStoreType, String trustStorePassword) {
				this.trustStorePath=trustStorePath;
				this.trustStoreType=trustStoreType;
				this.trustStorePassword=trustStorePassword;					
			}

        }
    }
}
