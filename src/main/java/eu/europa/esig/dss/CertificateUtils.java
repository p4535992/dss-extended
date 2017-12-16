package eu.europa.esig.dss;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.interfaces.DHPublicKey;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
/**
 * Concentriamo tutte le funzionalita nelle varie parti del codice relative ai certificati in questa classe
 * https://www.ibm.com/support/knowledgecenter/en/SSAW57_8.5.5/com.ibm.websphere.nd.doc/ae/tsec_sslcreatecuskeymgr.html
 *  
 * NOTA DA FINIRE
 */
public class CertificateUtils{
	
   private final static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertificateUtils.class);
	
   private X509KeyManager sourceKeyManager=null;
   private String alias;
 
	public CertificateUtils(X509KeyManager sourceKeyManager, String alias) {
		super();
		this.sourceKeyManager = sourceKeyManager;
		this.alias = alias;
	}

	  /**
	   * Builds the X509Certificate for the byte[].
	   * 
	   * @param encodedCertificate
	   * @return
	   * @throws IOException
	   * @throws CertificateException
	   */
	  public static X509Certificate toX509Certificate( byte[] encodedCertificate ) throws IOException, CertificateException{
	    
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    ByteArrayInputStream bais = new ByteArrayInputStream(encodedCertificate);
	    Certificate certificate = cf.generateCertificate( new BufferedInputStream(bais) );
	    bais.close();

	    return (X509Certificate) certificate;
	    
	}

	/**
	 * Metodo per prendere le informazioni relativa alla firma di un cetificato
	 * @param sFileKeystore
	 * @param passwordKeystore
	 * @param typeKeystore
	 * @return mappa dei principali valori dl certificato.
	 */
	public static Map<String,Serializable> getInfoCertificate(String sFileKeystore,String passwordKeystore,String typeKeystore){
		try {			
			Map<String,Serializable> map = new HashMap<String, Serializable>();
			if(typeKeystore==null || typeKeystore.isEmpty())typeKeystore = "jks";
			final KeyStore ks = KeyStore.getInstance(typeKeystore);
			ks.load(new FileInputStream(sFileKeystore), passwordKeystore.toCharArray());
			
			final Enumeration<String> aliases = ks.aliases();
			while(aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				final X509Certificate c = (X509Certificate) ks.getCertificate(alias);
				
				logger.debug("* Certificate info for alias : " + alias);				
				logger.debug("    - Version : " + c.getVersion());
				logger.debug("    - Serial number : " + c.getSerialNumber().toString(16));
				logger.debug("    - Subjetc DN : " + c.getSubjectDN());
				logger.debug("    - Issuer DN : " + c.getIssuerDN());
				logger.debug("    - Valide from : " + c.getNotBefore());
				logger.debug("    - Valide to : " + c.getNotAfter());
				logger.debug("    - Algorithm : " + c.getSigAlgName());
				
				map.put("alias", alias);
				map.put("version",c.getVersion());
			    map.put("serial",c.getSerialNumber().toString(16));
			    map.put("subjetc_dn",c.getSubjectDN().getName());
			    map.put("issuer_dn",c.getIssuerDN().getName());
			    map.put("start_from",c.getNotBefore());
			    map.put("end_to",c.getNotAfter());
			    map.put("algorithm",c.getSigAlgName());						   
			}
			 return map;
		} catch (KeyStoreException|NoSuchAlgorithmException|CertificateException|IOException e) {
			e.printStackTrace();
		}
		return null;
		
	}
		
//	/**
//	 * Metodo per prendere le informazioni relativa alla firma di un cetificato,
//	 * � utile per la verifica delle versioni bouncy castle con le firme utilizzate.
//	 * @param sFileKeystore
//	 * @param passwordKeystore
//	 * @param typeKeystore
//	 * @return mappa dei principali valori dl certificato.
//	 * @throws IOException 
//	 * @throws KeyStoreException 
//	 * @throws CertificateException 
//	 * @throws NoSuchAlgorithmException 
//	 * 
//	 * TODO da verificare per tutti i casi deriva da un vecchio metodo mai utilizzato si potrebbe anche cancellare
//	 */
//	@SuppressWarnings("unused")
//	public static Map<String,Serializable> getInfoCertificateWithBouncyCastle(String sFileKeystore,String passwordKeystore,String typeKeystore) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException{			
//			Provider provider = null;
//		    try {
//		        Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
//		        java.security.Security.insertProviderAt((java.security.Provider)c.newInstance(), 2000);
//		        //provider = "BC";
//		        provider = (Provider)c.newInstance();
//		        
//		    } catch(Exception e) {
//		        provider = null;
//		        // provider is not available }
//		    }		
//		    
//		    //KeyStore.getDefaultType()
//		    
//		    if(typeKeystore==null || typeKeystore.isEmpty())typeKeystore = "jks";
//			InputStream is = new FileInputStream(sFileKeystore);
//			
//			com.itextpdf.text.pdf.PdfReader reader = new com.itextpdf.text.pdf.PdfReader(is);
//			com.itextpdf.text.pdf.AcroFields af = reader.getAcroFields();
//		    List<String> names = af.getSignatureNames();
//		    KeyStore ks = KeyStore.getInstance(typeKeystore);
//		    ks.load(null, passwordKeystore.toCharArray());		    
//			List<Map<QName, Serializable>> aspects = new ArrayList<>();
//		    for (String name : names) {
//		    	com.itextpdf.text.pdf.security.PdfPKCS7 pk = af.verifySignature(name);
//		        X509Certificate certificate = pk.getSigningCertificate();
//		        
//		        //Set aspect properties for each signature
//		        Map<String, Serializable> map = new HashMap<String, Serializable>(); 
//		        if (pk.getSignDate() != null) map.put("PROP_DATE", pk.getSignDate().getTime());
//				map.put("PROP_CERTIFICATE_PRINCIPAL", certificate.getSubjectX500Principal().toString());
//			    map.put("PROP_CERTIFICATE_SERIAL_NUMBER", certificate.getSerialNumber().toString());
//			    map.put("PROP_CERTIFICATE_NOT_AFTER", certificate.getNotAfter());
//			    map.put("PROP_CERTIFICATE_ISSUER", certificate.getIssuerX500Principal().toString());   
//			    return map;
//		    }
//			return null;
//	}
//	

	public static PrivateKey getPrivateKey(String keystoreFormat,String pathToKeystore,String alias,String passwordKeystore) throws GeneralSecurityException, IOException {
		PrivateKey privateKey = null;
		if (privateKey == null) {
			privateKey = initializePrivateKey(keystoreFormat,pathToKeystore,alias,passwordKeystore);
		}
		return privateKey;
    }
	
	public static X509Certificate getCertX509(String keystoreFormat,String pathToKeystore,String alias,String passwordKeystore) throws GeneralSecurityException, IOException
	{
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		
		KeyStore keystore = getKeystore(passwordKeystore.toCharArray(),keystoreFormat,pathToKeystore);
	    java.security.cert.Certificate c = keystore.getCertificateChain(alias)[0];
		
	    
		InputStream in = new ByteArrayInputStream(c.getEncoded());
		X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
		
		return cert;
	}
	
	//Method to retrieve the PrivateKey form the KeyStore
    private static PrivateKey initializePrivateKey(String keystoreFormat,String pathToKeystore,String alias,String passwordKeystore) throws GeneralSecurityException, IOException {
       try{
	       KeyStore keystore = getKeystore(passwordKeystore.toCharArray(),keystoreFormat,pathToKeystore);
	       Certificate[] chain = keystore.getCertificateChain(alias);
	       if(chain != null && chain.length > 0){
	    	   return (PrivateKey) keystore.getKey(alias, passwordKeystore.toCharArray());
	       }else{
	    	   throw new java.lang.NullPointerException("The certificate with alias="+alias+ " is not been found");
	       }
       }catch(java.lang.NullPointerException ex){
    	   logger.error("Make sure to have set a password for the keystore on the object SignUtils");
    	   throw new IOException("Make sure to have set a password for the keystore on the object SignUtils",ex);
       }
    }
    
    /**
     * @deprecated use instead {@link CertificateUtils#getKeystore(File, String, String)}
     */
    public static KeyStore getKeystore(char[] password,String keystoreFormat,String pathToKeystore) throws GeneralSecurityException, IOException {
        //preferred keystore type impl. available in the env
        KeyStore keystore = KeyStore.getInstance(keystoreFormat);
        InputStream input = new FileInputStream(pathToKeystore);
        try {
          keystore.load(input, password);
        } catch (IOException e) {
          //Catch the Exception
        	e.printStackTrace();
        } finally {
             if (input != null) {
                 input.close();
             }
        }
        return keystore;
    }
    
    public static KeyStore getKeystore(File keyStoreFile,String keyStorePassword,String keystoreFormat) throws GeneralSecurityException, IOException {
        //preferred keystore type impl. available in the env
        KeyStore keystore = KeyStore.getInstance(keystoreFormat);
        InputStream input = new FileInputStream(keyStoreFile);
        try {
          keystore.load(input, keyStorePassword.toCharArray());
        } catch (IOException e) {
          //Catch the Exception
        	e.printStackTrace();
        } finally {
             if (input != null) {
                 input.close();
             }
        }
        return keystore;
    }
    
    public static CertStore buildCertsAndCRLsListToInsertInCMS(String keystoreFormat,String pathToKeystore,String alias,String passwordKeystore) throws GeneralSecurityException, IOException {
		ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
		certList.add(getCertX509(keystoreFormat,pathToKeystore,alias,passwordKeystore));

        //TODO : test this other way to store certificates
		// Certificate[] chain = userpkandcert.getX509CertificateChain();
        // CertStore certStore = CertStore.getInstance("Collection",new CollectionCertStoreParameters(Arrays.asList(chain)));

        // TODO : v0.2, implement CRL Retriever
		//if (cmssignparams.isInsertCRLs())
			//certList.add(getCRL);
		CertStore certstore = null;
		try {
			certstore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");		
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return certstore;
	}
    
    //https://www.javatips.net/api/usercenter-master/src/main/java/com/hwlcn/ldap/util/ssl/KeyStoreKeyManager.java
    //https://www.javatips.net/api/javax.net.ssl.keymanager
    public static KeyManager[] getKeyManagers(final String keyStoreFile, final char[] keySotrePassword, final String keyStoreFormat) throws KeyStoreException {
        if(keyStoreFile==null || keyStoreFile.isEmpty())throw new KeyStoreException("Il file <keyStoreFile> e' NULLO ");
        String type = keyStoreFormat;
        if (type == null) {
            type = KeyStore.getDefaultType();
        }
        final File f = new File(keyStoreFile);
        if (!f.exists()) {
            throw new KeyStoreException("Il file " + f.getAbsolutePath() + " non esiste");
        }
        final KeyStore ks = KeyStore.getInstance(type);
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(f);
            ks.load(inputStream, keySotrePassword);
        } catch (Exception e) {            
            throw new KeyStoreException(e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (Exception e) {
                	throw new KeyStoreException(e);
                }
            }
        }
        try {
            final KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(ks, keySotrePassword);
            return factory.getKeyManagers();
        } catch (Exception e) {           
        	throw new KeyStoreException(e);
        }
    }

	//https://github.com/coova/jradius/blob/master/extended/src/main/java/net/jradius/util/KeyStoreUtil.java
	public static KeyManager[] loadKeyManager(String type, InputStream in, String password) throws Exception
	{
		//loadBC();
		/*
		try {
			if (java.security.Security.getProvider("BC") == null){
				java.security.Security.addProvider(new BouncyCastleProvider());
			}else if(provider!=null){
				java.security.Security.addProvider(provider);
			}
		} catch (Throwable e) { }
		*/
		final char[] pwd = (password == null || password.length() == 0) ? null : password.toCharArray();

		if (type.equalsIgnoreCase("pem"))
		{
			Reader pemReader = new InputStreamReader(in);
			
			Object obj, keyObj=null, certObj=null, keyPair=null;

			while ((obj = pemReader.read()) != null)
			{
				if (obj instanceof X509Certificate) certObj = obj;
				else if (obj instanceof PrivateKey) keyObj = obj;
				else if (obj instanceof KeyPair) keyPair = obj;
			}
					
			if ((keyObj != null || keyPair != null) && certObj != null)
			{
				final PrivateKey key = keyPair != null ? ((KeyPair)keyPair).getPrivate() : (PrivateKey) keyObj;
				final X509Certificate cert = (X509Certificate) certObj;
				
				KeyStore ksKeys = KeyStore.getInstance("JKS");
				ksKeys.load(null, pwd == null ? "".toCharArray() : pwd);

				ksKeys.setCertificateEntry("", cert);
				ksKeys.setKeyEntry("", key, pwd == null ? "".toCharArray() : pwd, new Certificate[]{cert});
				KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
				kmf.init(ksKeys, pwd == null ? "".toCharArray() : pwd);

				return kmf.getKeyManagers();
				
/*
				return new KeyManager[] { new X509KeyManager()
			    {
					public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
						return "a";
					}
					public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
						return "a";
					}
					public X509Certificate[] getCertificateChain(String alias) {
						return new X509Certificate[] { cert };
					}
					public String[] getClientAliases(String keyType, Principal[] issuers) {
						return new String[] {"a"};
					}
					public PrivateKey getPrivateKey(String alias) {
						return key;
					}
					public String[] getServerAliases(String keyType, Principal[] issuers) {
						return new String[] {"a"};
					}
			    }};
    */
			}
			else
			{
				throw new RuntimeException("Could not load PEM source");
			}
		}

		KeyStore ksKeys = KeyStore.getInstance(type);
        ksKeys.load(in, pwd);

        Enumeration<String> aliases = ksKeys.aliases();
		while (aliases.hasMoreElements()) {
			String alias = (String) aliases.nextElement();
			System.err.println("KeyStore Alias: "+alias);
		}

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ksKeys, pwd);
        
        return kmf.getKeyManagers();
	}
	
	public static X509Certificate loadCertificateFromPEM(InputStream in, final char[] pwd) throws Exception
	{
		//loadBC();
		/*
		try {
			if (java.security.Security.getProvider("BC") == null){
				java.security.Security.addProvider(new BouncyCastleProvider());
			}else if(provider!=null){
				java.security.Security.addProvider(provider);
			}
		} catch (Throwable e) { }
		*/
        Reader pemReader = new InputStreamReader(in);

		Object obj;
		while ((obj = pemReader.read()) != null)
		{
			if (obj instanceof X509Certificate)
			{
				return (X509Certificate) obj;
			}
		}
		
		return null;
	}
		
	//https://github.com/coova/jradius/blob/master/extended/src/main/java/net/jradius/util/KeyStoreUtil.java
	public static TrustManager[] loadTrustManager(String type, InputStream in, String password) throws Exception
	{
		//loadBC();
		/*
		try {
			if (java.security.Security.getProvider("BC") == null){
				java.security.Security.addProvider(new BouncyCastleProvider());
			}else if(provider!=null){
				java.security.Security.addProvider(provider);
			}
		} catch (Throwable e) { }
		*/
		char[] pwd = (password == null || password.length() == 0) ? null : password.toCharArray();

		//if (type.equalsIgnoreCase("pem"))
		//{
			final X509Certificate cert = loadCertificateFromPEM(in, pwd);

			KeyStore ksKeys = KeyStore.getInstance("JKS");
			ksKeys.load(null, pwd == null ? "".toCharArray() : pwd);

			ksKeys.setCertificateEntry("", cert);

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ksKeys);

			return tmf.getTrustManagers();
			
		/*
					return new TrustManager[] { new X509TrustManager()
				    {
				        public void checkClientTrusted(X509Certificate[] chain, String authType) { }
				        public void checkServerTrusted(X509Certificate[] chain, String authType) { }
				        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[] { cert }; }
				    }};
		*/
		//}
	}
	
//   @Deprecated
//	private static void checkCert(String path) throws Exception{
//		//Security.addProvider(new BouncyCastleProvider());
//		FileInputStream fis = new FileInputStream(path);	
//		com.itextpdf.text.pdf.PdfReader reader = new com.itextpdf.text.pdf.PdfReader(fis);
//		com.itextpdf.text.pdf.AcroFields af = reader.getAcroFields();
//		assert af != null;	
//		for( String signatureName : af.getSignatureNames()){
//			com.itextpdf.text.pdf.security.PdfPKCS7 pk = af.verifySignature(signatureName);
//				Collection<CRL> crls= pk.getCRLs();
//				if(crls != null){
//					logger.debug("Found " + crls.size() + " crl");
//				}else{
//					logger.debug("No CRLS found");
//				}
//				Certificate[] chain = pk.getSignCertificateChain();
//				
//				boolean valid = pk.verify();
//				if(valid == true){
//					logger.debug("Il digest della firma e' valido");
//				}
//				
//				boolean tsImprint = pk.verifyTimestampImprint();
//				if(tsImprint == true){
//					logger.debug("La firma presenta la marca temporale incorporata. e' tsImprint");
//				}
//				boolean revocationValid = pk.isRevocationValid();
//				if(revocationValid == true){
//					logger.debug("Sono presenti Online Certificate Status e' revocationValid");
//				}
//				boolean ltv = pk.isTsp();
//				if(ltv == true){
//					logger.debug("TimeStamp e' ltv");
//				}	
//				Map<String, X509Certificate> certChain = new HashMap<String, X509Certificate>();				
//				for(int i = 0; i < chain.length; i++ ){				
//					Certificate currentCert = chain[i];
//					X509Certificate xCert = (X509Certificate)currentCert;
//					Principal principal = xCert.getSubjectX500Principal();
//			        String subjectDn = principal.getName();
//			        certChain.put(subjectDn, xCert);
//				}			     
//				for(int i = 0; i < chain.length; i++ ){					
//					Certificate currentCert = chain[i];
//					X509Certificate xCert = (X509Certificate)currentCert;
//					Principal principal = xCert.getSubjectX500Principal();
//			        String subjectDn = principal.getName();
//	//		        logger.debug("Subject " + subjectDn);		        
//			        // Get issuer
//			        X500Principal xprincipal = xCert.getIssuerX500Principal();
//			        String issuerDn = xprincipal.getName();
//	//		        logger.debug("Issuer " + issuerDn);						        
//	//		        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
//	//		        keystore.getCertificate(issuerDn);
//	//		       			        
//					try{
//						xCert.checkValidity();
//					}catch(Exception e){
//						logger.debug("Subject cert is invalid " + e.getMessage());
//					}									
//					boolean rootPb = false;
//					X509Certificate issuerCert =  certChain.get(issuerDn);
//					java.security.PublicKey rb =issuerCert.getPublicKey();
//					try{
//						currentCert.verify(rb);					
//					}catch(Exception e){
//						rootPb = true;
//						logger.debug("Issuer PB error " + e.getMessage());
//	//					e.printStackTrace();
//					}				
//					checkRevocation(pk, xCert, issuerCert, new Date());				
//					if(rootPb == false){
//						logger.debug( i + " " +   issuerDn + " -GRANTS- " + subjectDn);
//					}				
//					java.security.PublicKey pb = currentCert.getPublicKey();
//					boolean error = false;
//					try{		
//						currentCert.verify(pb);	
//					}catch(Exception e){
//						logger.debug("This is not a self-signed certificate "+ e.getMessage());
//						error = true;
//	//					e.printStackTrace();
//					}
//					if(error == false){
//						logger.debug("OK only if this is a self signed certificate!");
//					}
//	//				current.isRevoked(currentCert);
//				}
//	//		}
//		}
//	}

//    @Deprecated
//	public static void checkRevocation(com.itextpdf.text.pdf.security.PdfPKCS7 pkcs7,X509Certificate signCert, X509Certificate issuerCert, Date date)throws GeneralSecurityException, IOException {
//		    List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
//			if (pkcs7.getOcsp() != null){
//				ocsps.add(pkcs7.getOcsp());
//			}
////			List<VerificationOK> verification = new ArrayList<VerificationOK>();
//			OCSPVerifier ocspVerifier = new OCSPVerifier(null, ocsps);
//			List<VerificationOK> verification =ocspVerifier.verify(signCert, issuerCert, date);
//			if (verification.size() == 0) {
//				List<X509CRL> crls = new ArrayList<X509CRL>();
//				if (pkcs7.getCRLs() != null) {
//					for (CRL crl : pkcs7.getCRLs()){
//						crls.add((X509CRL)crl);
//					}
//				}
//					
//				CRLVerifier crlVerifier = new CRLVerifier(null, crls);
//				
//				crlVerifier.setOnlineCheckingAllowed(true);
//				try{
//					verification = crlVerifier.verify(signCert, issuerCert, date);
//				}catch(GeneralSecurityException e){
//					logger.debug("Errore di validazione " + e.getMessage());
//				}
//			}
//			if (verification.size() == 0) {
//				logger.debug("The signing certificate couldn't be verified");
//			}else {
//				logger.debug("Valid CRL");
//				for (VerificationOK v : verification){
//					logger.debug(v);
//					logger.debug(v.toString());
//				}
//			}
//	}
		
    public PKIXCertPathBuilderResult verifyCertificateChain(
   	     X509Certificate cert, 
   	     Set<X509Certificate> trustedRootCerts,
   	     Set<X509Certificate> intermediateCerts) throws GeneralSecurityException {

   	    // Create the selector that specifies the starting certificate
   	    X509CertSelector selector = new X509CertSelector(); 
   	    selector.setCertificate(cert);

   	    // Create the trust anchors (set of root CA certificates)
   	    Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
   	    for (X509Certificate trustedRootCert : trustedRootCerts) {
   	        trustAnchors.add(new TrustAnchor(trustedRootCert, null));
   	    }

   	    // Configure the PKIX certificate builder algorithm parameters
   	    PKIXBuilderParameters pkixParams = 
   	        new PKIXBuilderParameters(trustAnchors, selector);

   	    // Disable CRL checks (this is done manually as additional step)
   	    pkixParams.setRevocationEnabled(false);

   	    // Specify a list of intermediate certificates
   	    // certificate itself has to be added to the list 
   	    intermediateCerts.add(cert); 
   	    CertStore intermediateCertStore = CertStore.getInstance("Collection",
   	        new CollectionCertStoreParameters(intermediateCerts), "BC");
   	    pkixParams.addCertStore(intermediateCertStore);

   	    // Build and verify the certification chain
   	    CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
   	    PKIXCertPathBuilderResult result = 
   	        (PKIXCertPathBuilderResult) builder.build(pkixParams);
   	    return result;
   	}

   	//https://wwija.com/computer-internet-technology/3947534_how-do-i-check-if-an-x509-certificate-has-been-revoked-in-java.html
   public static void validateCertificate() throws Exception {

       String certificatePath = "C:\\Users\\user1\\Desktop\\test.cer";

       CertificateFactory cf = CertificateFactory.getInstance("X509");

       X509Certificate certificate = null;
       X509CRLEntry revokedCertificate = null;
       X509CRL crl = null;

       certificate = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certificatePath)));

       URL url = new URL("http://<someUrl from certificate>.crl");
       URLConnection connection = url.openConnection();

       try(DataInputStream inStream = new DataInputStream(connection.getInputStream())){

           crl = (X509CRL)cf.generateCRL(inStream);
       }

       revokedCertificate = crl.getRevokedCertificate(certificate.getSerialNumber());

       if(revokedCertificate !=null){
           System.out.println("Revoked");
       }
       else{
           System.out.println("Valid");
       }

   }
   
   public static Certificate getCertificate(KeyStore keyStore,String alias) throws KeyStoreException{ 
	   Certificate cert= keyStore.getCertificate(alias);
	   return cert;
   }
   
   public static Certificate getCertificate(Path keyStoreFile,String keyStorePassword,String keyStoreFormat, String alias) throws GeneralSecurityException, IOException{ 
	   KeyStore keyStore = getKeystore(keyStorePassword.toCharArray(), keyStoreFormat, keyStoreFile.toAbsolutePath().toString());
	   Certificate cert= keyStore.getCertificate(alias);
	   return cert;
   }
   
   public KeyPair getKeyPair(Path keyStoreFile,String keyStorePassword,String keyStoreFormat, String alias,String passwordCertificate) throws GeneralSecurityException, IOException {
	   KeyStore keyStore = getKeystore(keyStorePassword.toCharArray(), keyStoreFormat, keyStoreFile.toAbsolutePath().toString());
	   Certificate cert= keyStore.getCertificate(alias);
	   PrivateKey privateKey=(PrivateKey) keyStore.getKey(alias,passwordCertificate.toCharArray());
	   KeyPair kp=new KeyPair(cert.getPublicKey(),privateKey);
	   return kp;
  }
   
   public KeyPair getKeyPair(KeyStore keyStore,String keyStorePassword,String alias,String passwordCertificate) throws GeneralSecurityException {
	   Certificate cert= keyStore.getCertificate(alias);
	   PrivateKey privateKey=(PrivateKey) keyStore.getKey(alias,passwordCertificate.toCharArray());
	   KeyPair kp=new KeyPair(cert.getPublicKey(),privateKey);
	   return kp;
  }
   
   /**
    * Look up the Certificate of the signer of this signature.  
    * <p>Note that this only looks up the first signer. In MSSP signatures, 
    * there is only one, but in a general Pkcs1 case, there can be several. 
    *  
    * @return Signer certificate 
    * @throws CertificateEncodingException 
    * https://www.programcreek.com/java-api-examples/index.php?source_dir=laverca-master/src/core/fi/laverca/X509Util.java
    */ 
   public static java.security.cert.X509Certificate getSignerCert(X509Certificate x509Certificate) throws CertificateEncodingException { 
    return DERtoX509Certificate(x509Certificate.getEncoded()); 
   } 

   /**
    * Get the signer CN.  
    * <p>Equivalent to calling getSignerCert and 
    * then parsing out the CN from the certificate's Subject field. 
    * @return Signer's CN or null if there's a problem. 
    * https://www.programcreek.com/java-api-examples/index.php?source_dir=laverca-master/src/core/fi/laverca/X509Util.java
    */ 
   public static String getSignerCn(X509Certificate x509Certificate) { 
       try { 
           X509Certificate signerCert = getSignerCert(x509Certificate); 
           String dn = signerCert.getSubjectX500Principal().getName(); 

           String cn = null; 
           try { 
               LdapName ldapDn = new LdapName(dn); 
               List<Rdn> rdns = ldapDn.getRdns(); 
               for(Rdn r : rdns) { 
                   if("CN".equals(r.getType())) { 
                       cn = r.getValue().toString(); 
                   } 
               } 
           } catch(InvalidNameException e) { 
               logger.warn("Invalid name", e); 
           } 

           return cn; 
       } catch (Throwable t) { 
           logger.error("Failed to get Signer cert " + t.getMessage()); 
           return null; 
       } 
   } 
   
   public static X509Certificate DERtoX509Certificate(byte[] der) { 
       try { 
           ByteArrayInputStream bis = new ByteArrayInputStream(der); 
           CertificateFactory cf = CertificateFactory.getInstance("X.509"); 
           return (X509Certificate)cf.generateCertificate(bis); 
       } catch (Exception e) { 
           logger.error("", e); 
       } 
       return null; 
   } 

   public static byte[] X509CertificateToDER(X509Certificate cert) { 
       try { 
           return cert.getEncoded(); 
       } catch (Exception e) { 
    	   logger.error("", e); 
       } 
       return null; 
   } 

    
   /** return SHA-1 hash of the cert. */ 
   public static byte[] certHash(byte[] cert) { 
       if(cert == null) { 
           return null; 
       } 
        
       byte[] hash = null; 
       try { 
           MessageDigest md = MessageDigest.getInstance("SHA-256"); 
           hash = md.digest(cert); 
       } catch (Throwable t) { 
           // never happens 
       } 
        
       return hash; 
   } 
    
   public static String parseSubjectCn(X509Certificate cert) { 
       return parseSubjectName(cert, "CN"); 
   } 

   public static String parseSubjectName(X509Certificate cert, String rdnType) { 
       String dn = cert.getSubjectX500Principal().getName(); 
    
       String name = null; 
       try { 
           LdapName ldapDn = new LdapName(dn); 
           List<Rdn> rdns = ldapDn.getRdns(); 
           for(Rdn r : rdns) { 
               if(rdnType.equals(r.getType())) { 
                   name = r.getValue().toString(); 
               } 
           } 
       } 
       catch(InvalidNameException e) { 
           logger.error("",e); 
       } 
        
       return name; 
   } 
   
   //======================================================================================================================================================
   public static final String RDN_CN_TYPE = "cn";

	public static final String CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----";

	public static final String CERTIFICATE_END = "-----END CERTIFICATE-----";

	public static final int KEY_USAGE_LEN = 9;

	public static final String[] KEY_USAGE = new String[] { "digitalSignature",
			"nonRepudiation", "keyEncipherment", "dataEncipherment",
			"keyAgreement", "keyCertSign", "cRLSign", "encipherOnly",
			"decipherOnly" };
	
	public static final int KEY_USAGE_DIGITALSIGNATURE_INDEX	= 0;
	public static final int KEY_USAGE_NONREPUDIATION_INDEX		= 1;
	public static final int KEY_USAGE_KEYENCIPHERMENT_INDEX		= 2;
	public static final int KEY_USAGE_DATAENCIPHERMENT_INDEX	= 3;
	public static final int KEY_USAGE_KEYAGREEMENT_INDEX		= 4;
	public static final int KEY_USAGE_KEYCERTSIGN_INDEX			= 5;
	public static final int KEY_USAGE_CRLSIGN_INDEX				= 6;
	public static final int KEY_USAGE_ENCIPHERONLY_INDEX		= 7;
	public static final int KEY_USAGE_DECIPHERONLY_INDEX		= 8;

	public final static Hashtable<String, String> EXTENDED_KEY_USAGE_TABLE = new Hashtable<String, String>();
	static {
		EXTENDED_KEY_USAGE_TABLE.put("anyExtendedKeyUsage", "2.5.29.37.0");
		EXTENDED_KEY_USAGE_TABLE.put("serverAuth", "1.3.6.1.5.5.7.3.1");
		EXTENDED_KEY_USAGE_TABLE.put("clientAuth", "1.3.6.1.5.5.7.3.2");
		EXTENDED_KEY_USAGE_TABLE.put("codeSigning", "1.3.6.1.5.5.7.3.3");
		EXTENDED_KEY_USAGE_TABLE.put("emailProtection", "1.3.6.1.5.5.7.3.4");
		EXTENDED_KEY_USAGE_TABLE.put("ipsecEndSystem", "1.3.6.1.5.5.7.3.5");
		EXTENDED_KEY_USAGE_TABLE.put("ipsecTunnel", "1.3.6.1.5.5.7.3.6");
		EXTENDED_KEY_USAGE_TABLE.put("ipsecUser", "1.3.6.1.5.5.7.3.7");
		EXTENDED_KEY_USAGE_TABLE.put("timeStamping", "1.3.6.1.5.5.7.3.8");
		EXTENDED_KEY_USAGE_TABLE.put("ocspSigning", "1.3.6.1.5.5.7.3.9");
		EXTENDED_KEY_USAGE_TABLE.put("iKEIntermediate", "1.3.6.1.5.5.8.2.2");
		EXTENDED_KEY_USAGE_TABLE.put("microsoftSGC", "1.3.6.1.4.1.311.10.3.3");
		EXTENDED_KEY_USAGE_TABLE.put("netscapeSGC", "2.16.840.1.113730.4.1");
	}
		
	/**
	 * construit un objet Certificate à partir d'une chaîne encodée en base 64.
	 * qui est une représentation PEM d'un certificat. Il peut contenir ou non les
	 * délimteur "-----BEGIN/END CERTIFICATE-----".
	 * 
	 * @param b64String
	 *            chaine en base 64 représentant un certificat (PEM ou DER)
	 * @return certificat
	 * @throws IOException
	 *             dans le cas d'un problème de décodage du base 64
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static  Certificate getCertificate(String b64String)
			throws IOException, CertificateException {
		Certificate cert = null;
		if (!b64String.startsWith(CERTIFICATE_BEGIN)
				&& !b64String.endsWith(CERTIFICATE_END)) {
			byte[] certBytes = Base64.decodeBase64(b64String);
			if (certBytes == null || certBytes.length == 0) {
				throw new CertificateException("Decoded certificate is null or empty");
			}
			cert = getCertificate(certBytes);
		} else {
			InputStream is = new ByteArrayInputStream(
					b64String.getBytes());
			cert = getCertificate(is);
			is.close();
		}
		return cert;
	}

	/**
	 * construit un byte[] correspondant à un objet Certificate à partir d'une
	 * chaîne encodée en base 64. qui est une représentation PEM d'un
	 * certificat. Il peut contenir ou non les délimteur
	 * "-----BEGIN/END CERTIFICATE-----".
	 * 
	 * @param b64String
	 *            chaine en base 64 représentant un certificat (PEM ou DER)
	 * @return certificat
	 * @throws IOException
	 *             dans le cas d'un problème de décodage du base 64
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static  byte[] getCertificateEncoded(String b64String)
			throws IOException, CertificateException {
		byte[] certBytes = null;
		if (!b64String.startsWith(CERTIFICATE_BEGIN)
				&& !b64String.endsWith(CERTIFICATE_END)) {
			certBytes = Base64.decodeBase64(b64String);
			if (certBytes == null || certBytes.length == 0)
				throw new CertificateException("Decoded certificate is null or empty");
		} else {
			InputStream is = new ByteArrayInputStream(
					b64String.getBytes());
			Certificate cert = getCertificate(is);
			is.close();
			certBytes = cert.getEncoded();
		}
		return certBytes;
	}

	/**
	 * construit un objet Certificate à partir de sa réprésentation en tableau
	 * d'octets
	 * 
	 * @param certificateBytes
	 *            tableau représentant le certificat
	 * @return certificat
	 * @throws IOException
	 *             dans le cas d'un problème de manipulation du contenu du
	 *             tableau
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static  Certificate getCertificate(byte[] certificateBytes)
			throws IOException, CertificateException {
		InputStream byteArrayInputStream = new ByteArrayInputStream(
				certificateBytes);
		Certificate certificate = getCertificate(byteArrayInputStream);
		byteArrayInputStream.close();
		return certificate;
	}

	/**
	 * construit un object Certificate à partir d'un nom de fichier
	 * 
	 * @param fileName
	 *            chemin d'accès au fichier contenant le certificat
	 * @param informDER
	 *            true si le format d'entrée est DER, sinon false (PEM)
	 * @return certificat
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static  Certificate getCertificate(String fileName, boolean informDER)
			throws IOException, CertificateException {
		File cert = new File(fileName);
		if (informDER) {
			byte[] content = Files.readAllBytes(cert.toPath());
			return getCertificate(content);
		} else {
			return getPEMCertificate(cert);
		}
	}

	/**
	 * construit un objet Certificate à partir d'un fichier. Le fichier contient
	 * une représentation PEM d'un certificat. Il peut contenir ou non les
	 * délimteur "-----BEGIN/END CERTIFICATE-----".
	 * 
	 * @param file
	 *            fichier contenant le certificat
	 * @return certificat
	 * @throws IOException
	 *             dans le cas de problème de lecture du fichier
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static  Certificate getPEMCertificate(File file) throws IOException,
			CertificateException {
		byte[] fileBytes = Files.readAllBytes(file.toPath());
		String fileString = new String(fileBytes);
		if (!fileString.startsWith(CERTIFICATE_BEGIN)
				&& !fileString.endsWith(CERTIFICATE_END)) {
			return getCertificate(fileString);
		}
		InputStream fileInputStream = new FileInputStream(file);
		Certificate certificate = getCertificate(fileInputStream);
		fileInputStream.close();
		return certificate;
	}

	/**
	 * construit un objet Certificate à partir d'un fichier. Le fichier contient
	 * une représentation de certificat DER, ou PEM avec les délimiteurs
	 * "-----BEGIN/END CERTIFICATE-----"
	 * 
	 * @param file
	 *            fichier contenant le certificat
	 * @return certificat
	 * @throws IOException
	 *             dans le cas de problème de lecture du fichier
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 */
	public static  Certificate getCertificate(File file) throws IOException, CertificateException {
		InputStream fileInputStream = new FileInputStream(file);
		Certificate certificate = getCertificate(fileInputStream);
		fileInputStream.close();
		return certificate;
	}

	/**
	 * construit un objet Certificate à partir d'un stream. Utile pour la
	 * génération des certificats 'on the fly'.
	 * 
	 * @param inputStream
	 *            stream permettant de lire un certificat
	 * @return certificat
	 * @throws CertificateException
	 *             dans le cas d'un problème de parsing du certificat
	 * @throws IOException
	 *             dans le cas d'un problème de lecture du certificat
	 */
	private static  Certificate getCertificate(InputStream inputStream)
			throws CertificateException, IOException {
		Certificate certificate = null;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		//TODO Why do we keep on reading the input stream after parsing a certificate ?
		while (inputStream.available() > 0) {
			Certificate cert = cf.generateCertificate(inputStream);
			if (cert != null) {
				certificate = cert;
			}
		}
		if (certificate == null) {
			throw new CertificateException("Could not parse certificate");
		}
		return certificate;
	}

	/**
	 * calcule l'empreinte numérique d'un certificat
	 * 
	 * @param certificate
	 *            certificat dont on veut calculer l'empreinte
	 * @param algorithm
	 *            algorithme de hachage utilisé pour calculer l'empreinte
	 * @return tableau d'octet représentant empreinte numérique du certificat
	 * @throws CertificateException
	 *             en cad de problème d'encodage du certificat
	 * @throws NoSuchAlgorithmException
	 *             dans le cas où aucun provider n'est enregistré pour gérer
	 *             l'algorithme en entrée
	 */
	public static  byte[] getFingerPrint(Certificate certificate,
			String algorithm) throws CertificateException,
			NoSuchAlgorithmException {
		return getDigest(certificate.getEncoded(), algorithm);
	}

	/**
	 * finds key usage string from a java key usage array representation
	 * 
	 * @param keyUsageIndex
	 *            key usage java index
	 * @return key usage string
	 */
	public static  String getKeyUsage(int keyUsageIndex) {
		try {
			return KEY_USAGE[keyUsageIndex];
		} catch (Exception e) {
			throw new IllegalArgumentException(
					"Cannot find key usage string representation", e);
		}
	}
	
	/**
	 * 
	 * @param certificate
	 * @param keyUsageIndex
	 * @return Returns true if certificate has the key usage corresponding 
	 * to given key usage index, false otherwise.
	 */
	public static  boolean hasKeyUsage(X509Certificate certificate, int keyUsageIndex) {
		if (certificate == null) {
			throw new IllegalArgumentException("Argument certificate is null");
		}
		if (keyUsageIndex < 0) {
			throw new IllegalArgumentException("Argument keyUsageIndex is negative");
		}
		boolean[] usages = certificate.getKeyUsage();
		if (usages != null && usages.length > keyUsageIndex
				&& usages[keyUsageIndex])
			return true;
		else
			return false;
	}

	public static  String getExtendedKeyUsageOID(String keyUsage) {
		return (String) EXTENDED_KEY_USAGE_TABLE.get(keyUsage);
	}

	public static  String getExtendedKeyUsageName(String oid) {
		Enumeration k = EXTENDED_KEY_USAGE_TABLE.keys();
		while (k.hasMoreElements()) {
			String key = (String) k.nextElement();
			if (key.equals(oid)) {
				return EXTENDED_KEY_USAGE_TABLE.get(key);
			}
		}
		return null;
	}

	/**
	 * finds key usage java structure index from key usage string
	 * 
	 * @param keyUsageString
	 *            key usage string
	 * @return key usage index
	 */
	public static  int getKeyUsageIndex(String keyUsageString) {
		for (int i = 0; i < KEY_USAGE.length; i++) {
			if (keyUsageString.equalsIgnoreCase(KEY_USAGE[i]))
				return i;
		}
		throw new IllegalArgumentException(keyUsageString
				+ " does not represent a valid key usage");

	}
	
	/**
	 * gets certificate key length
	 * 
	 * @param certificate
	 *            certificate for which the key length must be returned
	 * @return certificate key length
	 * @throws KeyException
	 */
	public static  int getKeyLength(Certificate certificate) throws KeyException {
		if (certificate == null) {
			throw new IllegalArgumentException("certificate cannot be null");
		}
		return getKeyLength(certificate.getPublicKey());
	}

	/**
	 * gets public key length
	 * 
	 * @param publicKey
	 *            key for which the key length must be returned
	 * @return public key length
	 * @throws KeyException
	 */
	public static  int getKeyLength(PublicKey publicKey) throws KeyException {
		if (publicKey == null) {
			throw new IllegalArgumentException("key cannot be null");
		}
		int keyLength = -1;
		if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
			keyLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
		}
		if (publicKey instanceof java.security.interfaces.DSAPublicKey) {
			keyLength = ((DSAPublicKey) publicKey).getParams().getP()
					.bitLength();
		}
		if (publicKey instanceof javax.crypto.interfaces.DHPublicKey) {
			keyLength = ((DHPublicKey) publicKey).getParams().getP()
					.bitLength();
		}
		if (keyLength != -1) {
			return keyLength;
		}
		throw new KeyException("Cannot get key length");
	}

	public static  String getRdnValueFromDN(String dn, String rdnType) {
		String result = null;
		if (dn == null) {
			throw new IllegalArgumentException("DN cannot be null");
		}
		if (rdnType == null) {
			throw new IllegalArgumentException("RDN type cannot be null");
		}
		try {
			LdapName ldapdn = new LdapName(dn);
			for (Rdn rdn : ldapdn.getRdns()) {
				if (rdn.getType().equalsIgnoreCase(rdnType)) {
					result = (String) rdn.getValue();
					break;
				}
			}
		} catch (InvalidNameException e) {
			throw new IllegalArgumentException("Cannot parse DN value " + dn
					+ ", " + e.getMessage());
		}
		return result;
	}

	public static  String getCNFromDN(String dn) {
		return getRdnValueFromDN(dn, RDN_CN_TYPE);
	}

	public static  String getLabel(X509Certificate certificate) {
		if (certificate == null) {
			return null;
		}
		String dn = certificate.getSubjectDN().getName();
		String cn = getCNFromDN(dn);
		if (cn != null && cn.length() > 0) {
			return cn;
		}
		return dn;
	}

	public static  List<Certificate> getCertificateFullPath(
			Certificate certificate, List<Certificate> certificateList, Date referenceDate) throws Exception
			{
		CertStore certStore = null;
		try {
			certStore = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(certificateList));
		} catch (Exception e) {
			throw e;
		}

		return getCertificateFullPath(certificate, certStore, referenceDate);

	}

	public static  List<Certificate> getCertificateFullPath(
			Certificate targetCertificate, CertStore certStore, Date referenceDate) throws Exception
			{
		Collection<? extends Certificate> certificates = null;
		try {
			certificates = certStore.getCertificates(null);
		} catch (CertStoreException e) {
			throw e;
		}
		if (certificates == null || certificates.isEmpty()) {
			throw new CertPathBuilderException(
					"no certificates found to build certificate chain");
		}
		HashSet<TrustAnchor> rootCertificates = new HashSet<TrustAnchor>();
		for (Certificate certificate : certificates) {
			String issuerDN = ((X509Certificate) certificate).getIssuerDN()
					.getName();
			String subjectDN = ((X509Certificate) certificate).getSubjectDN()
					.getName();
			if (issuerDN.equals(subjectDN)) {
				rootCertificates.add(new TrustAnchor(
						(X509Certificate) certificate, null));
			}
		}

		X509CertSelector targetConstraints = new X509CertSelector();

		targetConstraints.setCertificate((X509Certificate) targetCertificate);

		PKIXBuilderParameters params = null;
		try {
			params = new PKIXBuilderParameters(rootCertificates,
					targetConstraints);
		} catch (Exception e) {
			throw e;
		}
		params.setRevocationEnabled(false);

		params.addCertStore(certStore);
		
		params.setDate(referenceDate);
		
		
		CertPathBuilder builder = null;
		try {
			builder = CertPathBuilder.getInstance("PKIX");
		} catch (NoSuchAlgorithmException e) {
			throw e;
		} 
//		catch (NoSuchProviderException e) {
//			ExceptionHandler.handle(e);
//		} 
		PKIXCertPathBuilderResult certPathBuilderResult = null;
		try {
			certPathBuilderResult = (PKIXCertPathBuilderResult) builder
					.build(params);
		} catch (Exception e) {
			String msg = null; 
			if (e.getCause()!=null) {
				if (e.getCause() instanceof CertificateExpiredException) {
					msg = "Certification path could not be validated because certificate is expired ["+e.getCause().getMessage()+"]";
				} else if (e.getCause().getCause()!=null && e.getCause().getCause() instanceof CertificateExpiredException) {
					msg = "Certification path could not be validated because certificate is expired ["+e.getCause().getCause().getMessage()+"]";
				} else if (e.getCause() instanceof CertificateNotYetValidException) {
					msg = "Certification path could not be validated because certificate is not yet valid ["+e.getCause().getMessage()+"]";
				} else if (e.getCause().getCause()!=null && e.getCause().getCause() instanceof CertificateNotYetValidException) {
					msg = "Certification path could not be validated because certificate is not yet valid ["+e.getCause().getCause().getMessage()+"]";
				}
			}
			throw new Exception(msg,e);
		}
		// TODO optimizations ?
		List<? extends Certificate> certFullPath = certPathBuilderResult
				.getCertPath().getCertificates();
		ArrayList<Certificate> certFullPathArrayList = new ArrayList<Certificate>(
				certFullPath.size() + 1);
		certFullPathArrayList.addAll(certFullPath);
		certFullPathArrayList.add(certPathBuilderResult.getTrustAnchor()
				.getTrustedCert());
		return certFullPathArrayList;
	}
	
	public static  Certificate getIssuerCertificate(
			Certificate certificate,
			CertStore... certificatesStores) throws CertStoreException, CertPathBuilderException {
		String issuerDN = ((X509Certificate) certificate).getIssuerDN()
				.getName();
		String issuerCN=getCNFromDN(issuerDN);
		Collection<Certificate> certificates = new ArrayList<Certificate>();
		if (certificatesStores!=null) {
			for (CertStore certificatesStore : certificatesStores) {
				if (certificatesStore!=null) {
					try {
						Collection<? extends Certificate> certToAdd = certificatesStore.getCertificates(null);
						if (certToAdd!=null) {
							certificates.addAll(certificatesStore.getCertificates(null));
						}
					} catch (CertStoreException e) {
						throw e;
					}
				}
			}
		}
		
		if (certificates == null || certificates.isEmpty()) {
			throw new CertPathBuilderException(
							"cannot find issuer certificate from empty certificate store");
		}

		for (Certificate issuercertificate : certificates) {
			String subjectDN = ((X509Certificate) issuercertificate).getSubjectDN()
					.getName();
			String subjectCN = getCNFromDN(subjectDN);
			if (issuerCN.equals(subjectCN)) {
				try {
					certificate.verify(issuercertificate.getPublicKey());
					return issuercertificate;
				} catch (Exception e) {
					// skip to the next candidate
				}
			}
		}
		throw new CertPathBuilderException(
				"cannot find issuer certificate of "
						+ ((X509Certificate) certificate).getSubjectDN()
								.getName()
						+ " issued by "
						+ ((X509Certificate) certificate).getIssuerDN()
								.getName());
		
	}
	/**
	 * This methode convert a X509 Distinguished Name String into a normalized
	 * form, as is to say, the resulting string :
	 * <ul>
	 * <li>have the RelativeDN elements in an ascendant order "emailaddress,
	 * sn, cn, ou, o, c", the input dn must contains at least two different RDN
	 * elements from this list of wellknown elements</li>
	 * <li>RDN separator is ", "</li>
	 * <li>case, quoted char and escape char in each RDN are preserved in the
	 * output string</li>
	 * <li>RDN value special characters are recognized ( escape character,
	 * etc.)</li>
	 * <li>Input DN must use "," as RDN separator (with or without space)</li>
	 * <li>the rdn name is converted to emailaddress</li>
	 * </ul>
	 * <p>
	 * Tested successfully with the following sample :
	 * <ul>
	 * <li>cn=\"Joë, Martîn\", ou=Sales, ou=Company\\, The, o=workl, c=fr</li>
	 * <li>c=fr,o=workl,ou=Company\\, The,ou=Sales\\0Dbo,cn=Joe Martin</li>
	 * <li>EMAILADDRESS=fdsfsd@fr.fr, CN=Joe marting, BL=CT, C=fr</li>
	 * <li>SN=toto,EMAILADDRESS=fdsfsd@fr.fr, CN=Joe marting,BL=CT, C=fr</li>
	 * <li>foofoo=fr,o=workl,ou=Company\\, The,ou=Sales,cn=Joe Martin</li>
	 * </ul>
	 */
	public static  String normalizeDN(String dn) {
		// First, split the dn into RDN elements, the X509NameTokenizer
		// recognize escape character
		X509NameTokenizerKeepChar rdnToken = new X509NameTokenizerKeepChar(dn);

		// Now guess the RDN elements order (from root to leaf or the contrary)
		// The guessing method consists in looking for wellknown RDN keys
		// and compares their absolute position in the string to determine if
		// the order is ascendant (emailaddress, sn, cn, ou, o, c)
		// or descendant (c, o, ou, cn, sn, emailaddress)
		String[] rdnName = { "emailaddress=", "sn=", "cn=", "ou=", "o=", "c=" };
		int orderIsUndefined = -1;
		int orderIsUnknown = 0;
		int orderIsAscendant = 1;
		int orderIsDescendant = 2;
		int presumedOrder = orderIsUnknown;
		String elt;
		int prevPosition = -1;
		ArrayList rdnArrayList = new ArrayList();
		while (rdnToken.hasMoreTokens()) {
			elt = rdnToken.nextToken();
			if (elt.startsWith("e=")) {
				elt = elt.replaceFirst("e=", "emailaddress=");
			} else if (elt.startsWith("E=")) {
				elt = elt.replaceFirst("E=", "EMAILADDRESS=");
			}
			rdnArrayList.add(elt);
		}
		int i = 0;
		while (i < rdnName.length && presumedOrder != orderIsUndefined) {
			for (int j = 0; j < rdnArrayList.size(); ++j) {
				elt = (String) rdnArrayList.get(j);
				if (elt.toLowerCase().startsWith(rdnName[i])) {
					if (prevPosition == -1) {
						prevPosition = j;
					} else if (prevPosition <= j) {
						if (presumedOrder == orderIsUnknown) {
							presumedOrder = orderIsAscendant;
						} else if (presumedOrder == orderIsDescendant) {
							presumedOrder = orderIsUndefined;
						}
					} else {
						if (presumedOrder == orderIsUnknown) {
							presumedOrder = orderIsDescendant;
						} else if (presumedOrder == orderIsAscendant) {
							presumedOrder = orderIsUndefined;
						}
					}
				}
			}
			++i;
		}
		StringBuffer outputDN = new StringBuffer(dn.length());
		if (presumedOrder != orderIsDescendant) {
			boolean isFirst = true;
			for (int k = 0; k < rdnArrayList.size(); ++k) {
				if (isFirst) {
					isFirst = false;
				} else {
					outputDN.append(", ");
				}
				outputDN.append((String) rdnArrayList.get(k));
			}
		} else {
			boolean isFirst = true;
			for (int k = rdnArrayList.size() - 1; k >= 0; --k) {
				if (isFirst) {
					isFirst = false;
				} else {
					outputDN.append(", ");
				}
				outputDN.append((String) rdnArrayList.get(k));
			}
		}
		return outputDN.toString();
	}
	/**
	 * class for breaking up an X500 Name into it's component tokens, ala
	 * java.util.StringTokenizer. We need this class as some of the lightweight
	 * Java environment don't support classes like StringTokenizer.
	 * <p>
	 * This modified version keeps escape and quote chars in output and suppress
	 * white space between rdn name and "="
	 */
	public static class X509NameTokenizerKeepChar {
		private String value;
		private int index;
		private char seperator;
		private StringBuffer buf = new StringBuffer();

		public X509NameTokenizerKeepChar(String oid) {
			this(oid, ',');
		}

		public X509NameTokenizerKeepChar(String oid, char seperator) {
			this.value = oid;
			this.index = -1;
			this.seperator = seperator;
		}

		public  boolean hasMoreTokens() {
			return (index != value.length());
		}

		public  String nextToken() {
			if (index == value.length()) {
				return null;
			}

			int end = index + 1;
			boolean quoted = false;
			boolean escaped = false;
			boolean namepart = true;
			boolean valuepart = false;

			buf.setLength(0);

			while (end != value.length()) {
				char c = value.charAt(end);

				if (c == '"') {
					if (!escaped) {
						quoted = !quoted;
					}
					buf.append(c);
					escaped = false;
				} else {
					if (escaped || quoted) {
						buf.append(c);
						escaped = false;
					} else if (c == '\\') {
						buf.append(c);
						escaped = true;
					} else if (c == seperator) {
						break;
					} else if (c == '=' && namepart) {
						buf.append(c);
						namepart = false;
						valuepart = true;
						end++;
						continue;
					} else if (c == ' ' || c == '\t') {
						if (!namepart && !valuepart) {
							buf.append(c);
						}
						end++;
						continue;
					} else {
						buf.append(c);
					}
				}
				if (valuepart) {
					valuepart = false;
				}
				end++;
			}

			index = end;
			return buf.toString().trim();
		}
	}
	
	public static  boolean isAuthorityCertificate(Certificate certificate) {		
		return (((X509Certificate) certificate).getBasicConstraints()!=-1);
	}
	
	//======================================================================================================
	
	/**
	 * @param x509crl
	 * @param x509certificate
	 * @param date
	 * @return
	 */
	public static  boolean isRevoked(X509CRL x509crl,
			X509Certificate x509certificate, Date date) {
		if (getRevocationDate(x509crl, x509certificate, date) != null) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * get a certificate revocation date  
	 * @param x509crl
	 * @param x509certificate
	 * @param date
	 * @return the rec
	 */
	public static  Date getRevocationDate(X509CRL x509crl,
			X509Certificate x509certificate, Date date) {

		BigInteger iSerialNumber = x509certificate.getSerialNumber();
		X509CRLEntry xEntry = x509crl.getRevokedCertificate(iSerialNumber);

		// Le certificat n'appartient pas à la liste de révocation
		if (xEntry == null)
			return null;

		// Le certificat appartient à la CRL. On va vérifier si le
		// certificat
		// a été révoqué avant ou après la date donnée en paramètre.
		Date revocationDate = xEntry.getRevocationDate();

		if (revocationDate.before(date)) {
			return revocationDate;
		} else {
			return null;
		}
	}

	public static  CRL getCRL(String b64String) throws IOException,
			CRLException, CertificateException {
		byte[] a = Base64.decodeBase64(b64String);
		ByteArrayInputStream bis = new ByteArrayInputStream(a);
		CRL crl = null;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		while (bis.available() > 0)
			crl = cf.generateCRL(bis);
		return crl;
	}

	public static  CRL getCRL(byte[] bytes) throws IOException, CRLException,
			CertificateException {
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		return getCRL(bis);
	}

	public static  CRL getCRL(File file) throws IOException,
			CertificateException, CRLException {
		InputStream fileInputStream = new FileInputStream(file);
		CRL crl = getCRL(fileInputStream);
		fileInputStream.close();
		return crl;
	}

	private static  CRL getCRL(InputStream inputStream) throws CRLException,
			IOException, CertificateException {
		CRL crl = null;
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		while (inputStream.available() > 0)
			crl = cf.generateCRL(inputStream);
		if (crl == null) {
			throw new CRLException("Could not parse crl");
		}
		return crl;
	}
	
	public static  byte[] getFingerPrint(CRL crl,
			String algorithm) throws CRLException,
			NoSuchAlgorithmException {
		return getDigest(((X509CRL)crl).getEncoded(), algorithm);
	}
	
	private static  ASN1Primitive getExtensionValue(X509CRL crl, String oid) throws IOException {
		if (crl == null) {
			return null;
		}
		byte[] bytes = crl.getExtensionValue(oid);
		if (bytes == null) {
			return null;
		}
		ASN1InputStream extValIs = new ASN1InputStream(new ByteArrayInputStream(bytes));
		ASN1OctetString octetStr = (ASN1OctetString) extValIs.readObject();
		extValIs = new ASN1InputStream(new ByteArrayInputStream(octetStr.getOctets()));
		return extValIs.readObject();
	}

	public static  BigInteger getCRLNumber(X509CRL crl) throws CRLException {
		BigInteger number = BigInteger.valueOf(0);
		try {
			ASN1Primitive obj = getExtensionValue(crl, X509Extension.cRLNumber.getId());
			CRLNumber crlnum = CRLNumber.getInstance(obj);
			number = crlnum.getCRLNumber();
		} catch (IOException e) {
			throw new CRLException("Error retrieving CRL number", e);
		}
		return number;
	}
	
//	public static  byte[] getAuthorityKeyIdentifier(X509CRL crl) throws CRLException {
//		byte[] result = null;
//		try {
//			byte[] extvalue = crl.getExtensionValue(X509Extension.authorityKeyIdentifier.getId());
//			if (extvalue != null) {
//				AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifierStructure(extvalue);
//				result = keyId.getKeyIdentifier();
//			}
//		} catch (IOException e) {
//			throw new CRLException("Error retrieving CRL authority key identifier", e);
//		}
//		return result;
//	}
//	
	/**
	 * Returns true if given certificate is CRL issuer, aka the issuer name and authority key
	 * identifier match and certificate has CRL signature key usage.
	 * @param crl
	 * @param acCertificate
	 * @return
	 * @throws CRLException
	 * @throws CertificateException 
	 */
	public static  boolean isCRLIssuer(X509CRL crl, X509Certificate acCertificate) throws CRLException, CertificateException {
		boolean result = false;
		
		if (!hasKeyUsage(acCertificate, KEY_USAGE_CRLSIGN_INDEX))
			return false;
		
		X500Principal issuerDN = crl.getIssuerX500Principal();
		if (acCertificate.getSubjectX500Principal().equals(issuerDN)) {
			byte[] issuerKeyIdASN1 = getAuthorityKeyIdentifier(crl);
			byte[] subjKeyIdANS1 = getSubjectKeyIdentifier(acCertificate);
			if (subjKeyIdANS1 != null && Arrays.equals(issuerKeyIdASN1, subjKeyIdANS1)) {
				result = true;
			}
		}
		return result;
	}
   
	/**
     * Checks whether given X.509 certificate is self-signed.
     */
    public static boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException
    {    
        // Try to verify certificate signature with its own public key
        PublicKey key = cert.getPublicKey();
        try {
			cert.verify(key);
			return true; 
		} catch (InvalidKeyException|SignatureException e) {
			return false;
		}
           
    }
    
    /**
     * Get the subject DN {@link String} from a certificate.
     * @param cert A {@link X509Certificate} to read the subject DN from
     * @return The {@link String} representing the subject for the {@link X509Certificate}
     */
    public static String getSubjectDN(X509Certificate cert) {
        String subjectDN = cert.getSubjectDN().getName();
        int dnStartIndex = subjectDN.indexOf("CN=") + 3;
        if (dnStartIndex > 0 && subjectDN.indexOf(",", dnStartIndex) > 0) {
            subjectDN = subjectDN.substring(dnStartIndex, subjectDN.indexOf(",", dnStartIndex)) + " (SN:"
                    + cert.getSerialNumber() + ")";
        }
        return subjectDN;
    }
    
    public static String getSubjectDN(KeyStore keyStore,String alias) throws KeyStoreException {
    	X509Certificate cert = ((X509Certificate)getCertificate(keyStore, alias));
        String subjectDN = cert.getSubjectDN().getName();
        int dnStartIndex = subjectDN.indexOf("CN=") + 3;
        if (dnStartIndex > 0 && subjectDN.indexOf(",", dnStartIndex) > 0) {
            subjectDN = subjectDN.substring(dnStartIndex, subjectDN.indexOf(",", dnStartIndex)) + " (SN:"
                    + cert.getSerialNumber() + ")";
        }
        return subjectDN;
    }

    /**
     * Get the issuer CN {@link String} from a certificate.
     * @param cert A {@link X509Certificate} to read the issuer CN from
     * @return The {@link String} representing the issuer CN for the {@link X509Certificate}
     */
    public static String getIssuerCN(X509Certificate cert) {
        String issuerCN = cert.getIssuerDN().getName();
        int cnStartIndex = issuerCN.indexOf("CN=") + 3;
        if (cnStartIndex > 0 && issuerCN.indexOf(",", cnStartIndex) > 0) {
            issuerCN = issuerCN.substring(cnStartIndex, issuerCN.indexOf(",", cnStartIndex));
        }
        return issuerCN;
    }
    
    public static String getIssuerCN(KeyStore keyStore,String alias) throws KeyStoreException {
    	X509Certificate cert = ((X509Certificate)getCertificate(keyStore, alias));
        String issuerCN = cert.getIssuerDN().getName();
        int cnStartIndex = issuerCN.indexOf("CN=") + 3;
        if (cnStartIndex > 0 && issuerCN.indexOf(",", cnStartIndex) > 0) {
            issuerCN = issuerCN.substring(cnStartIndex, issuerCN.indexOf(",", cnStartIndex));
        }
        return issuerCN;
    }
    
    
    //====================================================================================================

	public static  byte[] getDigest(byte []data, String hashAlgorithm) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
		return digest.digest(data);
	}
	
	public static  byte[] getDigest(File file, String algorithm)
			throws NoSuchAlgorithmException, IOException {
	
		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] digest;
		try {
			digest = getDigest(fileInputStream, algorithm);
			return digest;		
		} catch (IOException e) {
			throw e;
		} finally {
			try {
				if (fileInputStream != null) {
					fileInputStream.close();
				}
			} catch (IOException e) {
			}
		}
	}
	
	public static  byte[] getDigest(InputStream inputStream, String algorithm)
			throws IOException, NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		byte[] buffer = new byte[10000];
		int i = 0;
		while ((i = inputStream.read(buffer)) != -1) {
			md.update(buffer, 0, i);
		}
		return md.digest();
	}
	
	private static  byte[] getSubjectKeyIdentifier(X509Certificate certificate) throws CertificateException {
		byte[] result = null;
		try {
			byte[] extvalue = certificate.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
			if (extvalue != null) {
				SubjectKeyIdentifier keyId = new SubjectKeyIdentifier(extvalue);
				result = keyId.getKeyIdentifier();
			}
		} catch (Exception e) {
			throw new CertificateException("Error retrieving certificate subject key identifier for subject "
					+certificate.getSubjectX500Principal().getName(), e);
		}
		return result;
	}	
    
    private static  byte[] getAuthorityKeyIdentifier(X509Certificate certificate) throws CertificateException {
		byte[] result = null;
		try {
			byte[] extvalue = certificate.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
			if (extvalue != null) {
				AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifierStructure(extvalue);
				result = keyId.getKeyIdentifier();
			}
		} catch (IOException e) {
			throw new CertificateException("Error retrieving certificate authority key identifier for subject "
					+certificate.getSubjectX500Principal().getName(), e);
		}
		return result;
	}
	
	private static  byte[] getAuthorityKeyIdentifier(X509CRL crl) throws CRLException {
		byte[] result = null;
		try {
			byte[] extvalue = crl.getExtensionValue(X509Extension.authorityKeyIdentifier.getId());
			if (extvalue != null) {
				AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifierStructure(extvalue);
				result = keyId.getKeyIdentifier();
			}
		} catch (IOException e) {
			throw new CRLException("Error retrieving CRL authority key identifier", e);
		}
		return result;
	}
   
}
