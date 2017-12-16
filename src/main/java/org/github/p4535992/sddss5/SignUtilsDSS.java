package org.github.p4535992.sddss5;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import eu.europa.esig.dss.CertificateUtils;
import eu.europa.esig.dss.DSS5Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.TimeStamper;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESServiceSignatureExtended;
import eu.europa.esig.dss.client.NonceSource;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignatureScope;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESServiceSignatureExtended;

public class SignUtilsDSS{//<SP extends AbstractSignatureParameters> extends AbstractPkiFactoryTestDocumentSignatureService<SP> {
	
	private org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SignUtilsDSS.class);

	protected byte[] improntaFirmata;
	protected byte[] improntaNonFirmata;
	
	protected static final String BC = BouncyCastleProvider.PROVIDER_NAME;

	//Current DSS Settings
	protected eu.europa.esig.dss.DigestAlgorithm algorithm =  DigestAlgorithm.SHA256;;
	protected TSPSource tspSource;
	protected CertificateVerifier certificateVerifier;
	protected DSSPrivateKeyEntry currentDSSPrivateKeyEntry;
	private List<DSSPrivateKeyEntry> privateKeys;
	protected SignatureScope signatureScope;
	protected SignatureTokenType signatureTokenType;
	protected String format;
	protected SignaturePackaging signaturePackaging;
	protected SignatureLevel signatureLevel;
	protected SignatureTokenConnection signatureTokenConnection;
	protected SigningOperation signingOperation;
	protected TimeStampResponse tspTimeStampResponse;
			
	//DSS BLevel Settings
	protected SignatureImageParameters signatureImageParameters;
	protected SignerLocation signerLocation;
	protected Policy signaturePolicy;
	
	//Current keyStore Settings
	protected Provider provider;
	protected KeyStore keyStore;
	protected File keyStoreFile;
	protected String keyStorePassword;
	protected String keyStoreType;
	protected Certificate currentCertificate;
	protected String currentAliasCertificate;
	protected String currentSubjectDN;
	protected String currentIssuerCN;
	protected PrivateKey currentPrivateKey;
	protected PublicKey currentPublicKey;

	//TSP Settings
	protected String tspServer;
	protected String tspUsername;
	protected String tspPassword;
	protected String tspPolicyOid;	
	//https://github.com/vakho10/Java-TSA-TimeStamper
	protected TimeStamper timeStamper;
	
	//Proxy Settings
	protected String proxyHost;
	protected String proxyPort;
	protected String proxyUsername;
	protected String proxyPassword;
	
	//ESB Settings
	protected String urlWs = "http://servizi.abd.it:9090/testFirmaRemota?wsdl";
	protected String usernameWs;
	protected String passwordWs;
		
//	private static final String TSP_CONTEXT = "/tsp";
//	private static final String OCSP_CONTEXT = "/ocsp";
//	private static final String CRL_CONTEXT = "/crl";
//	private static final String CERTIFICATE_CONTEXT = "/certificate";
	
	//STATIC SETTNGS
	protected static final String TSP_SERVER_DEFAULT = "https://freetsa.org/tsr";	
	@Deprecated
	protected static final String TSP_SERVER_TUGRAZ = "http://tsp.iaik.tugraz.at/tsp/TspRequest";
	//protected static final String TSP_SERVER_ARUBA = "?????????????????";	
	@Deprecated
	protected static final String TSP_SERVER_SAFECREATIVE = "http://tsa.safecreative.org/";
	@Deprecated
	protected static final String TSP_SERVER_CERTUM = "http://time.certum.pl/";	
	@Deprecated
	protected static final String TSP_SERVER_CRYPTO = "http://www.cryptopro.ru/tsp/tsp.srf";

	protected static final String TSP_SERVER_COMODOCA = "http://timestamp.comodoca.com/authenticode";
	
	protected static String ALGORITHM_IDENTIFIER_DEFAULT = "SHA256WithRSA";
		
	//Additional Settings
	protected boolean isAutomatic = false;
	protected boolean isCounterSignature = false;
	protected boolean isDetached = false;
	protected boolean isNested = false;
	protected boolean isExtended = false;
	protected boolean isParallel = false;
	protected boolean isWithTimeStamp = false;
	protected boolean isWithLongTermDataCertificates =false;
	protected boolean isWithLongTermDataCertificatesAndArchiveTimestamp = false;
	protected boolean isOnlyMark = false;
	protected boolean isOnlyHash = false;
	
	//Pades Setttings
	protected String sigLocation;
	protected String sigReason;
	protected String sigSigner;
	/**
	 * @deprecated sembra inutilizzata da DSS
	 */
	protected String sigName;
	/**
	 * @deprecated sembra inutilizzata da DSS
	 */
	protected Date sigDate;
	
	//Other Settings
	@Deprecated
	protected static final int CSIZE = 0x5090 / 2;
	@Deprecated
	protected static final String ALGORITHM = "SHA-256";
	
	// ====================================================================================
	// CONSTRUCTOR
	//==============================================================================

	public SignUtilsDSS(byte[] fileToSign) throws IOException, URISyntaxException, GeneralSecurityException {
		this(SignatureLevel.CAdES_BASELINE_B,SignatureTokenType.PKCS12.name(),false,false,false,false,false,false,false,
				SigningOperation.SIGN,fileToSign,
				null,null,null,null,
				null,null,null,
				null,null
				);	
	}

	public SignUtilsDSS(SignatureLevel signatureLevel,SignatureTokenType signatureTokenType,
			boolean isDetached,boolean isNested,boolean isCounterSign,boolean isOnlyMark,boolean isAutomatic,boolean isParallel,boolean isOnlyHash,
			SigningOperation signingOperation,byte[] fileToSign) throws IOException, URISyntaxException, GeneralSecurityException {
		this(signatureLevel,signatureTokenType.name(),isDetached,isNested,isCounterSign,isOnlyMark,isAutomatic,isParallel,isOnlyHash,
				signingOperation,fileToSign,
				null,null,null,null,
				null,null,null,
				null,null
				);			
	}
	
	public SignUtilsDSS(SignatureLevel signatureLevel,String signatureTokenType,
			boolean isDetached,boolean isNested,boolean isCounterSign,boolean isOnlyMark,boolean isAutomatic,boolean isParallel,boolean isOnlyHash,
			SigningOperation signingOperation,byte[] fileToSign) throws IOException, URISyntaxException, GeneralSecurityException {
		this(signatureLevel,signatureTokenType,isDetached,isNested,isCounterSign,isOnlyMark,isAutomatic,isParallel,isOnlyHash,
				signingOperation,fileToSign,
				null,null,null,null,
				null,null,null,
				null,null
				);			
	}
	
	public SignUtilsDSS(SignatureLevel signatureLevel,String signatureTokenType,
			boolean isDetached,boolean isNested,boolean isCounterSign, boolean isOnlyMark,boolean isAutomatic,boolean isParallel,boolean isOnlyHash,
			SigningOperation signingOperation, byte[] fileToSign,
			File keyStoreFile,String keyStoreType,String keyStorePassword,String keyStoreAlias,
			String tspServer,String tspUsername, String tspPassword,
			String proxyHost,String proxyPort
			) throws IOException, URISyntaxException, GeneralSecurityException {
		super();
		this.provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		this.signatureLevel=signatureLevel;
		//TODO In attesa dell'aggiornamento della libraria DSS		
		//this.signatureTokenType= SignatureTokenType.valueOf(signatureTokenType);
		
		if(isDetached){			
			this.signaturePackaging = SignaturePackaging.DETACHED;			
		}else if(isNested){
			//IGNORA
			if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
				this.signaturePackaging = SignaturePackaging.ENVELOPING;		
			}else if(signatureLevel.getSignatureForm().equals(SignatureForm.XAdES)){
				this.signaturePackaging = SignaturePackaging.ENVELOPING;		
			}else if(signatureLevel.getSignatureForm().equals(SignatureForm.PAdES)){
				this.signaturePackaging = SignaturePackaging.ENVELOPED;		
			}		
			//this.signaturePackaging = SignaturePackaging.ENVELOPED;	
		}else if(isParallel){
			if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
				this.signaturePackaging = SignaturePackaging.ENVELOPING;		
			}else if(signatureLevel.getSignatureForm().equals(SignatureForm.XAdES)){
				this.signaturePackaging = SignaturePackaging.ENVELOPED;		
			}else if(signatureLevel.getSignatureForm().equals(SignatureForm.PAdES)){
				this.signaturePackaging = SignaturePackaging.ENVELOPED;		
			}
		}else{			
			this.signaturePackaging = SignaturePackaging.ENVELOPING;
		}	
		//OPZIONALI gia gestite da DSS
		if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES) && 
				signaturePackaging.equals(SignaturePackaging.ENVELOPED)){
			logger.error("not possible with CAdES. The original file is not extractable");
		}
		if(signatureLevel.getSignatureForm().equals(SignatureForm.XAdES) && 
				signaturePackaging.equals(SignaturePackaging.ENVELOPING)){
			logger.error("not possible with XAdES. The original file is embedded in the signature as ds:Object");
		}		
		
		if(signatureLevel.equals(SignatureLevel.CAdES_BASELINE_T) ||
				signatureLevel.equals(SignatureLevel.XAdES_BASELINE_T) ||
				signatureLevel.equals(SignatureLevel.PAdES_BASELINE_T) 
				){
			this.isWithTimeStamp=true;
		}else if(signatureLevel.equals(SignatureLevel.CAdES_BASELINE_LT) ||
				signatureLevel.equals(SignatureLevel.XAdES_BASELINE_LT) ||
				signatureLevel.equals(SignatureLevel.PAdES_BASELINE_LT) 
				){
			this.isWithLongTermDataCertificates=true;
		}else if(signatureLevel.equals(SignatureLevel.CAdES_BASELINE_LTA) ||
				signatureLevel.equals(SignatureLevel.XAdES_BASELINE_LTA) ||
				signatureLevel.equals(SignatureLevel.PAdES_BASELINE_LTA) 
				){
			this.isWithLongTermDataCertificatesAndArchiveTimestamp=true;
		}
		setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,keyStoreAlias);

		this.signingOperation = signingOperation;

		this.isAutomatic =  isAutomatic;
		this.isCounterSignature = isCounterSign;
		this.isDetached = isDetached;
		this.isNested = isNested;
		this.isExtended = signingOperation.equals(SigningOperation.EXTEND) ? true : false;
		this.isParallel = isParallel;
		this.isOnlyMark = isOnlyMark;
		this.isOnlyHash = isOnlyHash;
		
		if(improntaNonFirmata == null){
			improntaNonFirmata = DSS5Utils.digest(algorithm, fileToSign);
		}
	}

	// ====================================================================================
	// SETTER RESOURCES
	//==============================================================================
	
	public void setKeyStoreSource(File keyStoreFile,String keyStoreType,String keyStorePassword,String alias) throws IOException, GeneralSecurityException{
		if(keyStoreFile == null || !keyStoreFile.exists() || keyStoreFile.isDirectory() ||
				keyStoreType==null || keyStoreType.isEmpty() || 
				keyStorePassword==null || keyStorePassword.isEmpty()){
			if(this.keyStoreFile == null || !this.keyStoreFile.exists() || this.keyStoreFile.isDirectory() ||
					this.keyStoreType==null || this.keyStoreType.isEmpty() || 
					this.keyStorePassword==null || this.keyStorePassword.isEmpty()){
					//throw new DSSException("Wrong configuration of the keystore");
			}else{
			//ignore 
				throw new DSSException("Wrong configuration of the keystore");
			}
		}else{			
			KeyStore ks = loadKeyStore(keyStoreFile, keyStoreType, keyStorePassword, alias);
			this.keyStoreFile = keyStoreFile;		
			this.keyStoreType = keyStoreType;
			this.keyStorePassword = keyStorePassword;				
//			if(alias != null && !alias.isEmpty()){
//				this.currentAliasCertificate = alias;
//				this.currentSubjectDN = CertificateUtils.getSubjectDN(ks,alias);
//				this.currentIssuerCN = CertificateUtils.getIssuerCN(ks, alias);
//			}
			if(alias != null && !alias.isEmpty()){
				setAliasCertificateSource(ks,alias);
			}
			if(currentAliasCertificate != null && !currentAliasCertificate.isEmpty()){
				setAliasCertificateSource(ks,currentAliasCertificate);
			}
			this.keyStore=ks;
		}
	}
	
	public void setAliasCertificateSource(KeyStore ks,String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException{
		setAliasCertificateSource(ks.getCertificate(alias));
	}
	
	public void setAliasCertificateSource(Certificate certificate) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException{		
		this.currentAliasCertificate = DSS5Utils.getAlias(certificate, keyStoreFile, keyStoreType, keyStorePassword);
		this.currentSubjectDN = CertificateUtils.getSubjectDN((X509Certificate)certificate);
		this.currentIssuerCN = CertificateUtils.getIssuerCN((X509Certificate)certificate);		
	}
	
	private KeyStore loadKeyStore(final File keyStoreFile,
		    final String keyStoreType,final String keyStorePassword,String alias)
		    throws IOException, GeneralSecurityException {
	  logger.debug("Initializing key store: {}", keyStoreFile.getAbsolutePath());
	  final URI keystoreUri = keyStoreFile.toURI();
	  final URL keystoreUrl = keystoreUri.toURL();
	  //final KeyStore keyStore = KeyStore.getInstance(keyStoreType,new BouncyCastleProvider());
	  final KeyStore keyStore = KeyStore.getInstance(keyStoreType);
	  InputStream is = null;
	  try {
	    is = keystoreUrl.openStream();		  
		//keyStore = loadKeyStore(keyStoreFile, keyStoreType, keyStorePassword);
	    keyStore.load(is, null == keyStorePassword ? null : keyStorePassword.toCharArray());
	    logger.debug("Loaded key store");
	  } finally {
	    if (null != is) {
	      is.close();
	    }
	  }	
	  Map<String,Certificate> map = DSS5Utils.getSigningCertificates(keyStoreFile, keyStoreType, keyStorePassword);
	  if(alias != null && !alias.isEmpty()){
		  currentAliasCertificate = alias;
		  //currentCertificate = SDDSS5Utils.getCertificate(keyStoreFile, keyStoreType, keyStorePassword,  alias);
		  currentCertificate = keyStore.getCertificate(alias);
		  currentPrivateKey = (PrivateKey) keyStore.getKey(alias,  keyStorePassword.toCharArray());
	  }else if(currentAliasCertificate != null && !currentAliasCertificate.isEmpty()){
		  //currentCertificate = SDDSS5Utils.getCertificate(keyStoreFile, keyStoreType, keyStorePassword, currentAliasCertificate);
		  currentCertificate = keyStore.getCertificate(currentAliasCertificate);
		  currentPrivateKey = (PrivateKey) keyStore.getKey(currentAliasCertificate,  keyStorePassword.toCharArray());
	  }else{
		  //prendi il primo che capita
		  currentAliasCertificate = (String) Arrays.asList(map.keySet().toArray()).get(0);
		  currentCertificate = map.get(currentAliasCertificate);
		  currentPrivateKey = (PrivateKey) keyStore.getKey(currentAliasCertificate,  keyStorePassword.toCharArray());
	  
	  }
	  currentPublicKey = currentCertificate.getPublicKey();
	  if(currentPublicKey==null){
		  currentPublicKey = (PublicKey) DSS5Utils.getPublicKeys(keyStore, keyStorePassword).values().iterator().next();
	  }
	  //return KeyPair(publicKey, (PrivateKey) key);
	  return keyStore;
	}

    public void setTSPSource(String tspServer,String tspUsername,String tspPassword,DigestAlgorithm digestAlgorithm,String tspPolicyOid,String httpMethod,NonceSource nonceSource) throws NoSuchAlgorithmException, CloneNotSupportedException, IOException{
		if(tspServer==null || !tspServer.isEmpty()){
			this.tspServer=tspServer;
			this.tspUsername = tspUsername;
			this.tspPassword = tspPassword;
			this.tspPolicyOid = tspPolicyOid;			
			TimeStamper.Builder timeStamperBuilder = new TimeStamper.Builder()
				
					 //.setMessageDigest("SHA-1", TSPAlgorithms.SHA1)
		             .setMessageDigest(digestAlgorithm)
		             .setTsaUrl(this.tspServer);
					 if(httpMethod=="GET"){
						timeStamperBuilder.setRequestMethod("GET");
					 }else{
						timeStamperBuilder.setRequestMethod("POST");
					 }					 
					 if(nonceSource!=null){
						timeStamperBuilder.setNonCeSource(nonceSource);
					 }					 
					 if(proxyHost != null && !proxyHost.isEmpty() && proxyPort != null && !proxyPort.isEmpty()){					 
						 timeStamperBuilder.setProxy(proxyHost,Integer.valueOf(proxyPort),proxyUsername,proxyPassword);
					 }	          
		             //.setData("Some!".getBytes())
			 this.timeStamper=timeStamperBuilder.build();
		}else{
			logger.error("Can't set the TSPSource the TSPServer url is NULL or Empty");
		} 
    }
    
    public void setTSPSource(TimeStamper timeStamper) throws MalformedURLException, NoSuchAlgorithmException, IOException, CloneNotSupportedException {
		if(tspServer==null || !tspServer.isEmpty()){
			this.tspServer=timeStamper.getTsaUrl().toString();			
			this.tspPolicyOid = timeStamper.getPolicyOid().getId();			
			DigestAlgorithm digestAlgorithm = timeStamper.getDigestAlgorithm();
			String httpMethod = timeStamper.getRequestMethod();
			NonceSource nonceSource = timeStamper.getNonceSource();
			TimeStamper.Builder timeStamperBuilder = new TimeStamper.Builder()
					 //.setMessageDigest("SHA-1", TSPAlgorithms.SHA1)
		             .setMessageDigest(digestAlgorithm)
		             .setTsaUrl(tspServer);
					 if(tspUsername != null && !tspUsername.isEmpty() && tspPassword != null && !tspPassword.isEmpty()){
						 timeStamperBuilder.setTsaUsername(tspUsername);
						 timeStamperBuilder.setTsaPassword(tspPassword);
					 }
					 if(httpMethod=="GET"){
						timeStamperBuilder.setRequestMethod("GET");
					 }else{
						timeStamperBuilder.setRequestMethod("POST");
					 }					 
					 if(nonceSource!=null){
						timeStamperBuilder.setNonCeSource(nonceSource);
					 }					 
					 if(proxyHost != null && !proxyHost.isEmpty() && proxyPort != null && !proxyPort.isEmpty()){
						 if(proxyUsername != null && !proxyUsername.isEmpty() && proxyPassword != null && !proxyPassword.isEmpty()){
							 timeStamperBuilder.setProxy(proxyHost,Integer.valueOf(proxyPort),tspUsername,tspPassword);
						 }else{
							 timeStamperBuilder.setProxy(proxyHost,Integer.valueOf(proxyPort)); 
						 }
						 
					 }	          
		             //.setData("Some!".getBytes())
			 this.timeStamper=timeStamperBuilder.build();
		}else{
			logger.error("Can't set the TSPSource the TSPServer url is NULL or Empty");
		} 
    }

	/**
	 * @param signaturePolicyId The string representation of the OID of the signature policy to use when signing.
	 * @param algorithm
	 * @param description	
	 */
	public void setExplicitPolicy(String signaturePolicyId,DigestAlgorithm algorithm,String description){
		// Get and use the explicit policy
		//All these parameters are optional.
		DigestAlgorithm signaturePolicyHashAlgo = DigestAlgorithm.SHA256;
		String signaturePolicyDescription = description;
		byte[] signaturePolicyDescriptionBytes = signaturePolicyDescription.getBytes();
		byte[] digestedBytes = DSSUtils.digest(signaturePolicyHashAlgo, signaturePolicyDescriptionBytes);

		Policy policy = new Policy();
		if(signaturePolicyId != null){
			policy.setId(signaturePolicyId);			
		}
		if(description != null && description.isEmpty()){
			policy.setDescription(signaturePolicyDescription);			
		}
		if(signaturePolicyHashAlgo != null){
			policy.setDigestAlgorithm(signaturePolicyHashAlgo);		
		}
		if(digestedBytes != null && digestedBytes.length>0){
			policy.setDigestValue(digestedBytes);
		}
		this.signaturePolicy=policy;
	}
	
	public void setImplicitPolicy(){
		setExplicitPolicy("",null,null);
	}
	
	public void setProxySource(String proxyHost,String proxyPort,String proxyUsername,String proxyPassword){
		this.proxyUsername = proxyUsername;
		this.proxyPassword = proxyPassword;
		setProxySource(proxyHost, proxyPort);
	}
	
	public void setProxySource(String proxyHost,String proxyPort){
		if(proxyHost==null || !proxyHost.isEmpty()){
			this.proxyHost=proxyHost;		
			if(proxyPort==null || !proxyPort.isEmpty()){
				this.proxyPort = proxyPort;
				System.setProperty("http.proxySet", "true");
		        System.setProperty("http.proxyHost", proxyHost);
		        System.setProperty("http.proxyPort", proxyPort);
		        System.setProperty("https.proxyHost", proxyHost);
		        System.setProperty("https.proxyPort", proxyPort);		        
//		        System.setProperty("https.protocols", "SSL,TLSv1,SSLv3");
		        
		        //Reinisializziamo il timestamper se era stato inizilizato prima
		        if(timeStamper!=null){
		        	//setTSPSource(timeStamper);
					timeStamper.setProxy(this.proxyHost, Integer.valueOf(this.proxyPort),this.proxyUsername,this.proxyPassword);
		        }
			}else{
				logger.error("Can't set the Proxy Server the Proxy port is NULL or Empty");
			}
		}else{
			logger.error("Can't set the Proxy Server the Proxy url is NULL or Empty");
		}
	}
	
	public void setPadesInfo(String location,String reason,String signerDelegate){
		this.sigLocation=location;
		this.sigReason=reason;
		this.sigSigner=signerDelegate;
	}
	
	public void setSignatureImage(String textToVisualize){
		setSignatureImage(textToVisualize,200,500,new Font("serif", Font.PLAIN, 14),Color.BLUE);
	}
	
	public void setSignatureImage(String textToVisualize,int axisX,int axisY,Font font,Color color){
		// Initialize visual signature
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		// the origin is the left and top corner of the page
		imageParameters.setxAxis(axisX);
		imageParameters.setyAxis(axisY);

		// Initialize text to generate for visual signature
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setFont(font);
		textParameters.setTextColor(color);
		textParameters.setText(textToVisualize);
		imageParameters.setTextParameters(textParameters);
	}
	
	public void setSignerLocation(String country,String stateOrProvince,String locality,
			String street,String postalCode,List<String> postalAddress){
		SignerLocation location = new SignerLocation();
		if(country!=null && !country.isEmpty())location.setCountry(country);
		if(stateOrProvince!=null && !stateOrProvince.isEmpty())location.setStateOrProvince(stateOrProvince);
		if(postalAddress!=null && !postalAddress.isEmpty())location.setPostalAddress(postalAddress);
		if(locality!=null && !locality.isEmpty())location.setLocality(locality);
		if(street!=null && !street.isEmpty())location.setStreet(street);
		if(postalCode!=null && !postalCode.isEmpty())location.setPostalCode(postalCode);
		this.signerLocation = location;
	}
	
	public void setPolicy(String id,DSSDocument dssDocument,String qualifier,String description){
		if(id==null || id.isEmpty() || dssDocument==null)throw new DSSException("You can' set a Policy without ID or a Document");
		Policy policy = new Policy();
		policy.setId(id);
		policy.setDigestAlgorithm(algorithm);
		policy.setDigestValue(dssDocument.getDigest(algorithm).getBytes());
		if(description!=null && !description.isEmpty())policy.setDescription(description);
		if(qualifier!=null && !qualifier.isEmpty())policy.setQualifier(qualifier);
		//policy.setSpuri(spuri);		
		this.signaturePolicy = policy;
	}
	
	public void setWsClient(String urlWs,String usernameWs,String passwordWs) throws IOException{
		this.urlWs = urlWs;
		this.usernameWs = usernameWs;
		this.passwordWs = passwordWs;	
	}

	//=========================================================================================================
	// PREPARE FUNCTION DSS
	//=====================================================================================
//	private void prepareSignLocal(File fileToSign)
//			throws IOException, DSSException {
//		prepareSignLocal(
//				Files.readAllBytes(fileToSign.toPath()),keyStoreFile,keyStoreType,keyStorePassword,null,
//				tspServer,tspUsername,tspPassword,
//				proxyHost,proxyPort);
//	}
//	
//	private void prepareSignLocal(byte[] fileToSign)
//			throws IOException, DSSException {
//		prepareSignLocal(
//				fileToSign,keyStoreFile,keyStoreType,keyStorePassword,null,
//				tspServer,tspUsername,tspPassword,
//				proxyHost,proxyPort);
//	}
	
	private void prepareSignLocal(
			byte[] fileToSign,
			File keyStoreFile,String keyStoreType,String keyStorePassword,
			String tspServer,String tspUsername,String tspPassword,
			String proxyHost,String proxyPort)
			throws IOException, DSSException {
		prepareSignLocal(
				fileToSign,
				keyStoreFile,keyStoreType,keyStorePassword,null,
				tspServer,tspUsername,tspPassword,
				proxyHost,proxyPort);
	}
	
	private void prepareSignLocal(
			byte[] fileToSign,
			File keyStoreFile,String keyStoreType,String keyStorePassword,String keyStoreCN,
			String tspServer,String tspUsername,String tspPassword,
			String proxyHost,String proxyPort)
			throws DSSException,IOException{
		try{
			//loadKeyStore(keyStoreFile, keyStoreType, keyStorePassword,"");
			
			if(keyStoreFile == null || !keyStoreFile.exists() || keyStoreFile.isDirectory()){
				throw new IOException("Keystore File is not setted");
			}
			if(keyStoreType == null || keyStoreType.isEmpty()){
				throw new IOException("Keystore Type is not setted");
			}
			if(keyStorePassword == null || keyStorePassword.isEmpty()){
				throw new IOException("Keystore Password is not setted");
			}		
			
			//GET BASIC VALUES
			//DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
			//String claimedRole = "";
			// Get a token connection based on a pkcs12 file commonly used to store private
			// keys with accompanying public key certificates, protected with a password-based
			// symmetric key -
			// Return AbstractSignatureTokenConnection signingToken
			SignatureTokenConnection signingToken = null;
			
			// final File fileToSign = model.getSelectedFile();
			// SignatureTokenType signatureTokenType = SignatureTokenType.PKCS12;
			//SignatureTokenConnection signingToken = SDDSS3Utils.prepareTokenConnection(fileToSign, signatureTokenType,storePassword);
			if(signatureTokenType!=null){
				signingToken = DSS5Utils.prepareTokenConnection(keyStoreFile, signatureTokenType,keyStorePassword);
			}else{
				signingToken = DSS5Utils.prepareTokenConnection(keyStoreFile, "JKS",keyStorePassword);
			}
			// and it's first private key entry from the PKCS12 store
			// Return DSSPrivateKeyEntry privateKey *****
		    List<DSSPrivateKeyEntry> privateKeys = signingToken.getKeys();
		    if(privateKeys==null || privateKeys.isEmpty()){
		    	throw new DSSException("The keystore you try to use not have any private key to use for the signature");
		    }	   
			DSSPrivateKeyEntry privateKey = DSS5Utils.preparePrivateKeyChooser(signingToken, this.currentIssuerCN);
			if(privateKey== null){
			    throw new DSSException("The private key you try to use not have any private key to use for the signature, check if you use the right alias");
		    }
			CertificateVerifier certificateVerifier = 
					DSS5Utils.prepareCertificateVerifier(
							DSS5Utils.prepareKeystoreCertificateSource(keyStoreFile,keyStoreType,keyStorePassword)			
			);		
			
			//String tspServer = "https://freetsa.org/tsr";
	
			//String tspServer = "http://tsatest1.digistamp.com/tsa";
			//OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
			//byte[] toDigest = Files.readAllBytes(fileToSign.toPath());
			byte[] toDigest = fileToSign;
		    TSPSource tspSource = null;
		    if(this.timeStamper!=null){
		    	tspSource = DSS5Utils.prepareOnlineTSPSource(this.timeStamper, toDigest);
		    }else{
		    	throw new DSSException("Something wrong the timestamper must be not null");
		    	//tspSource = DSS5Utils.prepareOnlineTSPSource(tspServer,toDigest,this.algorithm,tspUsername,tspPassword,proxyHost,proxyPort,null,null,tspPolicyOid,"POST",null);
		    }
		    //TimeStampResponse timeStampResponse = DSS5Utils.prepareTimeStampResponse(tspServer, toDigest,tspUsername, tspPassword, proxyHost, proxyPort);
		    TimeStampResponse timeStampResponse = DSS5Utils.prepareTimeStampResponse(timeStamper, toDigest);
		    
		    //OPTIONAL
			/*	
			if (claimedRole != null && !claimedRole.isEmpty()) {
				parameters.setClaimedSignerRole(claimedRole);
			}
	
			if (signaturePolicyValue != null && !signaturePolicyValue.isEmpty()) {
				final byte[] hashValue = Base64.decodeBase64(getSignaturePolicyValue());
				final SignatureParameters.Policy policy = parameters.getSignaturePolicy();
				policy.setHashValue(hashValue);
				policy.setId(getSignaturePolicyId());
				DigestAlgorithm digestAlgo = DigestAlgorithm.forName(getSignaturePolicyAlgo());
				policy.setDigestAlgo(digestAlgo);
			}
			*/
		    this.certificateVerifier = certificateVerifier;
		    //this.digestAlgorithm = digestAlgorithm;
		    this.currentDSSPrivateKeyEntry = privateKey;
		    this.signatureTokenConnection = signingToken;
		    this.tspSource = tspSource;
		    this.tspTimeStampResponse = timeStampResponse;
		    
		    this.keyStoreFile = keyStoreFile;
		    this.keyStorePassword = keyStorePassword;
		    this.keyStoreType = keyStoreType;	  
		    
		    this.tspServer = tspServer;
		    this.tspUsername = tspUsername;
		    this.tspPassword = tspPassword;
		    
		    this.proxyHost = proxyHost;
		    this.proxyPort = proxyPort;  
		    
	
		}catch(URISyntaxException | GeneralSecurityException | NumberFormatException | TSPException e){
			throw new DSSException(e);
		}
	}
	
	//=============================================================================================================
	
	public byte[] sign(File fileToSign)throws DSSException {				
		DSSDocument toSignDocument = new FileDocument(fileToSign);		
		//String nameTragetFile = fileToSign.getParentFile().getAbsolutePath()+File.separator+DSSUtils.getFinalFileName(toSignDocument, signingOperation, signatureLevel);
		String pathTargetFile = 
				DSS5Utils.prepareTargetFileName(
						fileToSign.getAbsolutePath(),this.signatureLevel, true,
						isCounterSignature , isExtended, isParallel,isOnlyMark);
		File signedFile = new File(pathTargetFile);	
		try {
			return sign(Files.readAllBytes(fileToSign.toPath()),new FileOutputStream(signedFile));
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
	
	public byte[] sign(File fileToSign,File targetFile) throws DSSException {		
		try {
			return sign(Files.readAllBytes(fileToSign.toPath()), new FileOutputStream(targetFile));
		} catch (IOException e) {
			throw new DSSException(e);
		}	
	}
	
	public byte[] sign(byte[] fileToSign,OutputStream targetSource){			
		byte[] signedData = null;
		try{
			
			switch(signatureLevel.getSignatureForm()){
				case CAdES: 
				{
					prepareSignLocal(fileToSign, 
							keyStoreFile,keyStoreType,keyStorePassword,
							tspServer,tspUsername,tspPassword,
							proxyHost,proxyPort);
					signedData = signLocalCades(fileToSign,targetSource);
					break;
				}
				case XAdES:
				{
					prepareSignLocal(fileToSign, 
							keyStoreFile,keyStoreType,keyStorePassword,
							tspServer,tspUsername,tspPassword,
							proxyHost,proxyPort);
					signedData = signLocalXades(fileToSign,targetSource);
					break;
				}
				case PAdES:
				{
					prepareSignLocal(fileToSign, 
							keyStoreFile,keyStoreType,keyStorePassword,
							tspServer,tspUsername,tspPassword,
							proxyHost,proxyPort);
					signedData = signLocalPades(fileToSign,targetSource);
					break;
				}
			}
		}catch(DSSException ex){
			throw ex;
		} catch (IOException e) {
			throw new DSSException(e);
//		} catch (URISyntaxException e) {
//			throw new DSSException(e);
//		} catch (GeneralSecurityException e) {
//			throw new DSSException(e);
		}
		return signedData;
	}
	
	private byte[] signLocalCades(byte[] fileToSign, OutputStream targetSource) {	
		DSSDocument dssddocument = new InMemoryDocument(fileToSign);
		final CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(signatureLevel);	
		parameters.setSignaturePackaging(signaturePackaging);
		parameters.setDigestAlgorithm(algorithm);	
		parameters.setSigningCertificate(currentDSSPrivateKeyEntry.getCertificate());
		parameters.setCertificateChain(currentDSSPrivateKeyEntry.getCertificateChain());	
		if(signatureImageParameters!=null){
			logger.warn("You can set the SignatureImage only for Pades Signature");
		}
		if(signerLocation!=null){
			parameters.bLevel().setSignerLocation(signerLocation);
		}
		if(signaturePolicy!=null){
			parameters.bLevel().setSignaturePolicy(signaturePolicy);
		}
		CAdESServiceSignatureExtended service = new CAdESServiceSignatureExtended(certificateVerifier);					
		service.setTspSource(tspSource);	
		DSSDocument signedDocument;
		try {		
			ToBeSigned dataToSign = null;
			SignatureValue signatureValue =  null;
			if(isOnlyHash){
				//DigestDocument hashDocument = DSS5Utils.toDSSDocumentUsingDigest(dssddocument, algorithm);
				InMemoryDocument hashDocument = new InMemoryDocument(DSS5Utils.digest(algorithm, dssddocument));
				dataToSign = service.getDataToSign(hashDocument,parameters);					
				signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);
			}else{
				dataToSign = service.getDataToSign(dssddocument,parameters);					
				signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);
			}
			logger.debug("Signature value : " + Utils.toBase64(signatureValue.getValue()));
			if(isCounterSignature){
				SignerId signatureToCounter = new JcaSignerId(currentDSSPrivateKeyEntry.getCertificate().getCertificate());					
				signedDocument = service.counterSignDocument(dssddocument, parameters, signatureValue, signatureToCounter);			
			}else if(isParallel){				
				signedDocument = service.signDocument(dssddocument, parameters, signatureValue);
			}else if(isNested){				
				signedDocument = ((CAdESServiceSignatureExtended)service).nestedSignDocument(dssddocument, parameters, signatureValue,currentPrivateKey);			
			}else if(isOnlyMark){
				signedDocument = mark(signatureLevel, dataToSign.getBytes());
			}else if(isExtended){				
				signedDocument = service.extendDocument(dssddocument, parameters);	
			}else{
				signedDocument = service.signDocument(dssddocument, parameters, signatureValue);		
			}

			signedDocument.writeTo(targetSource);
			
			logger.debug("SUCCESS Signature " + signatureLevel.name());
			return IOUtils.toByteArray(signedDocument.openStream());
		} catch (DSSException dssException) {
			throw dssException;		
		} catch (IOException e) {		
			throw new DSSException(e);
		} catch (TSPException e) {
			throw new DSSException(e);
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		} catch (GeneralSecurityException e) {
			throw new DSSException(e);
		} catch (CMSException e) {
			throw new DSSException(e);
		}finally{
			if(targetSource != null){
				IOUtils.closeQuietly(targetSource);
			}
		}
	}
	
	private byte[] signLocalXades(byte[] fileToSign, OutputStream targetSource) throws DSSException{	
		DSSDocument documentToSign = new InMemoryDocument(fileToSign);		
		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSigningCertificate(currentDSSPrivateKeyEntry.getCertificate());
		parameters.setCertificateChain(currentDSSPrivateKeyEntry.getCertificateChain());
		parameters.setSignaturePackaging(signaturePackaging);
		parameters.setSignatureLevel(signatureLevel);
		parameters.setDigestAlgorithm(algorithm);
		if(signatureImageParameters!=null){			
			logger.warn("You can set the SignatureImage only for Pades Signature");
		}
		if(signerLocation!=null){
			parameters.bLevel().setSignerLocation(signerLocation);
		}
		if(signaturePolicy!=null){
			parameters.bLevel().setSignaturePolicy(signaturePolicy);
		}
		XAdESServiceSignatureExtended service = new XAdESServiceSignatureExtended(certificateVerifier);			
		service.setTspSource(tspSource);	
		DSSDocument signedDocument;
		try {	
			ToBeSigned dataToSign = null;
			SignatureValue signatureValue =  null;
			if(isOnlyHash){
				//DigestDocument hashDocument = DSS5Utils.toDSSDocumentUsingDigest(dssddocument, algorithm);
				InMemoryDocument hashDocument = new InMemoryDocument(DSS5Utils.digest(algorithm, documentToSign));
				dataToSign = service.getDataToSign(hashDocument,parameters);					
				signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);
			}else{
				dataToSign = service.getDataToSign(documentToSign,parameters);					
				signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);
			}
			//ToBeSigned dataToSign = service.getDataToSign(documentToSign,parameters);	
			//SignatureValue signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);			
			logger.debug("Signature value : " + Utils.toBase64(signatureValue.getValue()));			
			if(isCounterSignature){
				//SignerId signatureToCounter = new JcaSignerId(currentDSSPrivateKeyEntry.getCertificate().getCertificate());									
				//signedDocument = ((XAdESServiceCounterSignature)service).counterSignDocument(documentToSign, parameters, signatureValue, signatureToCounter);	
				//signedDocument = ((XAdESServiceCounterSignature)service).counterSignDocument(documentToSign, parameters, signatureValue, currentPrivateKey);
				
				//NOTE USE XADES4J
				signedDocument = service.counterSignDocument(documentToSign, parameters,signatureValue, this.keyStoreFile,this.keyStoreType,this.keyStorePassword);
			}else if(isNested){
				//NOTE USE XADES4J
				//Starnge eu.europa.esig.dss.xades.signature.EnvelopedSignatureBuilder
				signedDocument = service.nestedSignDocument(documentToSign, parameters, signatureValue, 
						keyStoreFile,keyStoreType,keyStorePassword,tspServer,tspUsername,tspPassword);
			}else{
				signedDocument = service.signDocument(documentToSign, parameters, signatureValue);
			}
			signedDocument.writeTo(targetSource);
			
			logger.debug("SUCCESS Signature " + signatureLevel.name());
			return IOUtils.toByteArray(signedDocument.openStream());
		} catch (DSSException dssException) {
			throw dssException;
		} catch (IOException ioException) {
			throw new DSSException(ioException);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		} catch (CMSException e) {
			throw new DSSException(e);
		}catch(TransformerFactoryConfigurationError e){
			throw new DSSException(e);		
		}finally{
			if(targetSource != null){
				IOUtils.closeQuietly(targetSource);
			}
		}
	}
	
	private byte[] signLocalPades(byte[] fileToSign, OutputStream targetSource) {	
		DSSDocument dssddocument = new InMemoryDocument(fileToSign);
		final PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSignatureLevel(signatureLevel);	
		parameters.setSignaturePackaging(signaturePackaging);
		parameters.setDigestAlgorithm(algorithm);	
		parameters.setSigningCertificate(currentDSSPrivateKeyEntry.getCertificate());
		parameters.setCertificateChain(currentDSSPrivateKeyEntry.getCertificateChain());

		if(signatureImageParameters!=null){
			parameters.setSignatureImageParameters(signatureImageParameters);
		}
		if(signerLocation!=null){
			logger.warn("You can set the SignerLocation only for Cades/Xades Signature");
		}
		if(signaturePolicy!=null){
			parameters.bLevel().setSignaturePolicy(signaturePolicy);
		}
		if(sigLocation != null){
			parameters.setLocation(sigLocation);
		}
		if(sigReason!=null){
			parameters.setReason(sigReason);
		}
		if(sigSigner!=null){
			parameters.setContactInfo(sigSigner);
		}
		PAdESService service = new PAdESService(certificateVerifier);
		
		service.setTspSource(tspSource);	
		DSSDocument signedDocument;
		try {		
			ToBeSigned dataToSign = null;
			SignatureValue signatureValue =  null;
			if(isOnlyHash){
				//DigestDocument hashDocument = DSS5Utils.toDSSDocumentUsingDigest(dssddocument, algorithm);
				InMemoryDocument hashDocument = new InMemoryDocument(DSS5Utils.digest(algorithm, dssddocument));
				dataToSign = service.getDataToSign(hashDocument,parameters);					
				signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);
			}else{
				dataToSign = service.getDataToSign(dssddocument,parameters);					
				signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);
			}
			//ToBeSigned dataToSign = service.getDataToSign(dssddocument,parameters);					
			//SignatureValue signatureValue = signatureTokenConnection.sign(dataToSign,algorithm,currentDSSPrivateKeyEntry);			
			logger.debug("Signature value : " + Utils.toBase64(signatureValue.getValue()));
			if(isCounterSignature){
				//service = new PAdESServiceCounterSignature(certificateVerifier);	
				throw new DSSException("The countersign is not abilitate for the Pades Signature");
			}else if(isNested){
				//TODO to implement
				signedDocument = service.signDocument(dssddocument, parameters, signatureValue);		
			}else{
				signedDocument = service.signDocument(dssddocument, parameters, signatureValue);		
			}
			signedDocument.writeTo(targetSource);
			logger.debug("SUCCESS Signature " + signatureLevel.name());
			return IOUtils.toByteArray(signedDocument.openStream());
		} catch (DSSException dssException) {
			throw dssException;		
		} catch (IOException e) {		
			throw new DSSException(e);
		}finally{
			if(targetSource != null){
				IOUtils.closeQuietly(targetSource);
			}
		}
	}
	
	
	private DSSDocument mark(SignatureLevel signatureLevel, byte[] dataToMark) throws IOException, TSPException, OperatorCreationException, NoSuchAlgorithmException, CertificateException{
		if(DSS5Utils.validateCertificateTSP((X509Certificate)currentCertificate)){
			//TODO capire perchè il timestamping remoto fallisce sempre 
			logger.debug("The certificate you use for the timestamping is valid");
			
			final byte[] digestValue = DSSUtils.digest(algorithm, dataToMark);
			TimeStampResponse markedFile = DSS5Utils.prepareTimeStampResponse(this.timeStamper, digestValue);
			TimeStampToken token = markedFile.getTimeStampToken();
			if(token != null){
				byte[] encoding = token.getEncoded();
				logger.debug("timestamp: "+token.getTimeStampInfo().getGenTime());
                logger.debug("serial n. "+token.getTimeStampInfo().getSerialNumber());
                logger.debug("tsa: "+token.getTimeStampInfo().getTsa());
                logger.debug("policy: "+token.getTimeStampInfo().getPolicy());	
                return new InMemoryDocument(encoding);
			}else{
				throw new DSSException("The certificate you use for the timestamping is valid but the token is NULL");
			}
		}else{
			//Il certificato in esame non e' valido lo rendiamo valido per programmazione delle
			//bouncycastle
			logger.debug("The certificate you use for the timestamping is not valid we forced to work");
			byte[] encoding = markForced(signatureLevel,dataToMark);
			logger.debug(Arrays.toString(encoding));
			return new InMemoryDocument(encoding);
		}
	}
	
	/**
	 * Metodo che per poter marcare con un certificato esistente, ma non abilitatom alm timestamping necessità di dover 
	 * essere forzato con le bouncycastle
	 * https://stackoverflow.com/questions/21376359/how-to-build-a-rfc-3161-time-stamp-using-bouncy-castle
	 * 
	 * @return
	 * @throws OperatorCreationException 
	 * @throws NoSuchAlgorithmException 
	 * @throws TSPException 
	 * @throws IOException 
	 * @throws CertificateException 
	 */
	private byte[] markForced(SignatureLevel signatureLevel, byte[] dataToMark) throws OperatorCreationException, NoSuchAlgorithmException, TSPException, IOException, CertificateException{		
		final byte[] digestValue = DSSUtils.digest(timeStamper.getDigestAlgorithm(), dataToMark);
		TimeStampRequestGenerator tsReqGen = new TimeStampRequestGenerator();
		//TimeStampRequest tsReq = tsReqGen.generate(CMSAlgorithm.SHA256, digestValue);	ù
		TimeStampRequest tsReq = tsReqGen.generate(timeStamper.getPolicyOid(), digestValue);	
		AlgorithmIdentifier algorithmIdentifier = new DefaultDigestAlgorithmIdentifierFinder().find(timeStamper.getDigestAlgorithm().getName());//new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP);//AlgorithmIdentifier.getInstance(ASN1Sequence.getInstance(digestValue));
		DigestCalculator dgCalc = new JcaDigestCalculatorProviderBuilder().build().get(algorithmIdentifier);
		ContentSigner signer = new JcaContentSignerBuilder(ALGORITHM_IDENTIFIER_DEFAULT).build(currentPrivateKey);
		//Certificate certificateOri = DSS5Utils.getCertificate(keyStoreFile, keyStorePassword, "JKS", "testFirma");				
	    //Certificate currentCertificateToExtend = DSS5Utils.buildEndEntityCert(currentPublicKey, currentPrivateKey, (X509Certificate) currentCertificate);							
		int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week
		X509Certificate certificateToExtend = (X509Certificate) currentCertificate;
		String name = "CN="+currentIssuerCN;
	    X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
	            certificateToExtend.getSubjectX500Principal(),
	            BigInteger.ONE,
	            new Date(System.currentTimeMillis()),
	            new Date(System.currentTimeMillis() + VALIDITY_PERIOD),
	            new X500Principal(name),
	            currentPublicKey);

	    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

	    certBldr.addExtension(Extension.authorityKeyIdentifier, true, extUtils.createAuthorityKeyIdentifier(certificateToExtend))
	            .addExtension(Extension.subjectKeyIdentifier, true, extUtils.createSubjectKeyIdentifier(currentPublicKey))
	            .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
	            .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation))
	            //.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_codeSigning, KeyPurposeId.id_kp_timeStamping}));
	            .addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

	    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(currentPrivateKey);
	    Certificate currentCertificateToExtend = new JcaX509CertificateConverter().setProvider(BC).getCertificate(certBldr.build(contentSigner));
	    
	    SignerInfoGenerator siGen = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, (X509Certificate)currentCertificateToExtend);
		ASN1ObjectIdentifier policy = timeStamper.getPolicyOid();//new ASN1ObjectIdentifier("1.2.3.4.5.6"); // Replace by your timestamping policy OID
		TimeStampTokenGenerator tstGen = new TimeStampTokenGenerator(siGen, dgCalc, policy);
		
		/* Set the parameters e.g. set the accuracy or include the signing certificate */
		TimeStampToken token = tstGen.generate(tsReq, DSS5Utils.generateSerialNumber(), new Date());
		byte[] encoding = token.getEncoded();
		return encoding;
	}
	
//	protected String buildFinalName(String sourceName,boolean returnFullPath){
//		String ext = FilenameUtils.getExtension(sourceName);
//		String newExt = "";
//		if(ext.equalsIgnoreCase("p7m")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else{newExt = ".p7m";}
//		}
//		else if(ext.equalsIgnoreCase("p7s")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else{newExt = ".p7s";}
//		}
//		else  if(ext.equalsIgnoreCase("p7s")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else{newExt = ".p7s";}
//		}
//		else  if(ext.equalsIgnoreCase("m7m")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else{newExt = ".m7m";}
//		}
//		else  if(ext.equalsIgnoreCase("tsr")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else{newExt = ".tsr";}
//		}
//		else  if(ext.equalsIgnoreCase("tsd")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else{newExt = ".tsd";}
//		}
//		else  if(ext.equalsIgnoreCase("pdf")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else if(isOnlyMark){
//				newExt = ".tsr";
//			}
//			else{
//				if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
//					newExt = ".p7m";
//				}else if(signatureLevel.getSignatureForm().equals(SignatureForm.PAdES)){
//					newExt = "";
//				}
//			}
//		}
//		else  if(ext.equalsIgnoreCase("xml")){
//			if(isCounterSignature || isExtended || isParallel){newExt = "";}
//			else if(isOnlyMark){
//				newExt = ".tsr";
//			}
//			else{
//				if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
//					newExt = ".p7m";
//				}else if(signatureLevel.getSignatureForm().equals(SignatureForm.XAdES)){
//					newExt = "";
//				}
//			}
//		}else {
//			if(isOnlyMark){
//				newExt = ".tsr";
//			}
//		    else if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
//				newExt = ".p7m";
//			}
//			else {
//				newExt = "";
//			}
//		}
//		//DSSUtils.getFinalFileName(originalFile, operation, level)
//		if(returnFullPath){
//			return FilenameUtils.getFullPath(sourceName)+File.separator+FilenameUtils.getName(sourceName)+newExt;
//		}else{
//			return FilenameUtils.getName(sourceName)+newExt;
//		}
//	}

	//=====================================
	//GETTER AND SETTER DSS
	//=====================================
	
	public byte[] getImprontaFirmata() {
		return improntaFirmata;
	}

	public byte[] getImprontaNonFirmata() {
		return improntaNonFirmata;
	}

	public eu.europa.esig.dss.DigestAlgorithm getAlgorithm() {
		return algorithm;
	}

	public TSPSource getTspSource() {
		return tspSource;
	}

	public CertificateVerifier getCertificateVerifier() {
		return certificateVerifier;
	}

	public DSSPrivateKeyEntry getCurrentDSSPrivateKeyEntry() {
		return currentDSSPrivateKeyEntry;
	}

	public SignatureScope getSignatureScope() {
		return signatureScope;
	}

	public SignatureTokenType getSignatureTokenType() {
		return signatureTokenType;
	}

	public String getFormat() {
		return format;
	}

	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	public SignatureTokenConnection getSignatureTokenConnection() {
		return signatureTokenConnection;
	}

	public SigningOperation getSigningOperation() {
		return signingOperation;
	}

	public SignatureImageParameters getSignatureImageParameters() {
		return signatureImageParameters;
	}

	public SignerLocation getSignerLocation() {
		return signerLocation;
	}

	public Policy getSignaturePolicy() {
		return signaturePolicy;
	}

	public Provider getProvider() {
		return provider;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public File getKeyStoreFile() {
		return keyStoreFile;
	}

	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	public String getKeyStoreType() {
		return keyStoreType;
	}

	public Certificate getCurrentCertificate() {
		return currentCertificate;
	}

	public String getCurrentAliasCertificate() {
		return currentAliasCertificate;
	}

	public String getCurrentSubjectDN() {
		return currentSubjectDN;
	}

	public String getCurrentIssuerCN() {
		return currentIssuerCN;
	}

	public PrivateKey getCurrentPrivateKey() {
		return currentPrivateKey;
	}

	public PublicKey getCurrentPublicKey() {
		return currentPublicKey;
	}

	public String getTspServer() {
		return tspServer;
	}

	public String getTspUsername() {
		return tspUsername;
	}

	public String getTspPassword() {
		return tspPassword;
	}

	public String getProxyHost() {
		return proxyHost;
	}

	public String getProxyPort() {
		return proxyPort;
	}

	public String getUrlWs() {
		return urlWs;
	}

	public String getUsernameWs() {
		return usernameWs;
	}

	public String getPasswordWs() {
		return passwordWs;
	}

	public boolean isCounterSignature() {
		return isCounterSignature;
	}

	public boolean isDetached() {
		return isDetached;
	}

	public boolean isNested() {
		return isNested;
	}

	public boolean isExtended() {
		return isExtended;
	}

	public boolean isParallel() {
		return isParallel;
	}

	public boolean isWithTimeStamp() {
		return isWithTimeStamp;
	}

	public boolean isWithLongTermDataCertificates() {
		return isWithLongTermDataCertificates;
	}

	public boolean isWithLongTermDataCertificatesAndArchiveTimestamp() {
		return isWithLongTermDataCertificatesAndArchiveTimestamp;
	}

	public String getSigLocation() {
		return sigLocation;
	}

	public String getSigReason() {
		return sigReason;
	}

	public String getSigSigner() {
		return sigSigner;
	}

	public String getSigName() {
		return sigName;
	}

	public Date getSigDate() {
		return sigDate;
	}
	
	//============================================================================================
	
	
	public static void main(String[] args) throws IOException, URISyntaxException, GeneralSecurityException, OperatorCreationException, CloneNotSupportedException{
		
		//SET PROXY
	  	System.setProperty("http.proxySet", "true");
        System.setProperty("http.proxyHost", "192.168.1.188");
        System.setProperty("http.proxyPort", "3128");
        System.setProperty("https.proxyHost", "192.168.1.188");
        System.setProperty("https.proxyPort", "3128");
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader(); 
        
       
		//CADES FILES
    	File fileToSign = new File("C:\\Users\\tenti\\Desktop\\test_firma\\new 3.txt");
		File targetFilepParallel = new File("C:\\Users\\tenti\\Desktop\\test_firma\\new 3.txt.p7m");
		File targetFilepParallelHash = new File("C:\\Users\\tenti\\Desktop\\test_firma\\new 3.txt.hash.p7m");
		File targetFileCounter = new File("C:\\Users\\tenti\\Desktop\\test_firma\\new 3.txt.counter.p7m");
		File targetFileNested = new File("C:\\Users\\tenti\\Desktop\\test_firma\\new 3.txt.nested.p7m.p7m");
		File targetFileNestedCounter = new File("C:\\Users\\tenti\\Desktop\\test_firma\\new 3.txt.counter.nested.p7m.p7m");
				
        //XADES FILE
		File fileXadesToSign = new File("C:\\Users\\tenti\\Desktop\\test_firma\\xml_example.xml");		
		File fileXadesParallel = new File("C:\\Users\\tenti\\Desktop\\test_firma\\xml_example.signed.xml");
		File fileXadesParallelDouble = new File("C:\\Users\\tenti\\Desktop\\test_firma\\xml_example.signed2.xml");
		File fileXadesCounter = new File("C:\\Users\\tenti\\Desktop\\test_firma\\xml_example.signed.counter.xml");
		File fileXadesNested = new File("C:\\Users\\tenti\\Desktop\\test_firma\\xml_example.signed.nested.xml");
		
		//PADES FILE
		File filePadesToSign = new File("C:\\Users\\tenti\\Desktop\\test_firma\\pdf_example.pdf");		
		File filePadesParallel = new File("C:\\Users\\tenti\\Desktop\\test_firma\\pdf_example.signed.pdf");
		File filePadesParallel2 = new File("C:\\Users\\tenti\\Desktop\\test_firma\\pdf_example.signed.signed.pdf");
		File filePadesParallelHash = new File("C:\\Users\\tenti\\Desktop\\test_firma\\pdf_example.signed.hash.pdf");
		
		//KEYSTORE/TRUSTORE CONFIGURATION
		
		//File fileToSign = new File(SignUtilsSDDSS5.class.getResource("/test_firma/new 3.txt").toURI());
        //File targetFile = new File(SignUtilsSDDSS5.class.getResource("/test_firma/new 3.txt.p7m").toURI());
        //File keyStoreFile = new File(SignUtilsSDDSS5.class.getResource("/test_firma/testKeystore.jks").toURI());
		
		 File keyStoreFile = new File("C:\\Users\\tenti\\Desktop\\test_firma\\testKeystore5.jks");
		String keyStorePassword = "changeit";
		String keyStoreType = "JKS";
		Map<String,Certificate> map = DSS5Utils.getSigningCertificates(keyStoreFile, "JKS", keyStorePassword);
		Certificate certificate = DSS5Utils.getCertificate(keyStoreFile, keyStorePassword, "JKS", "TSA_SERVER");
		
		//#########################
		// CADES EXAMPLE
		//########################		
		/*
		//TEST CADES FIRMA PARALLLELA
		SignUtilsDSS s = new SignUtilsDSS(SignatureLevel.CAdES_BASELINE_B,"JKS",false,false,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		s.setProxySource("192.168.1.188","3128");
		s.sign(fileToSign, targetFilepParallel);
		//TEST CADES FIRMA COUNTER
		SignUtilsDSS s2 = new SignUtilsDSS(SignatureLevel.CAdES_BASELINE_B,"JKS",false,false,true,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s2.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s2.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		s2.setProxySource("192.168.1.188","3128");
		s2.sign(targetFilepParallel,targetFileCounter);
		//TEST CADES FIRMA NESTED
		SignUtilsDSS s6 = new SignUtilsDSS(SignatureLevel.CAdES_BASELINE_B,"JKS",false,true,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s6.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s6.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		s6.setProxySource("192.168.1.188","3128");
		s6.sign(targetFilepParallel);
		//TEST CADES FIRMA NESTED SU COUNTER
		SignUtilsDSS s4 = new SignUtilsDSS(SignatureLevel.CAdES_BASELINE_B,"JKS",false,true,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s4.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s4.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		s4.setProxySource("192.168.1.188","3128");
		s4.sign(targetFileCounter,targetFileNestedCounter);
		//TEST MARCATURA
		SignUtilsDSS s14 = new SignUtilsDSS(SignatureLevel.CAdES_BASELINE_B,"JKS",false,false,false,true,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s14.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s14.setProxySource("192.168.1.188","3128");
		s14.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);	
		s14.sign(fileToSign);
		*/
		//TEST CADES SOLO HASH FIRMA PARALLLELA
		/*
		SignUtilsDSS s24 = new SignUtilsDSS(SignatureLevel.CAdES_BASELINE_B,"JKS",false,false,false,false,false,false,true,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s24.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s24.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		s24.setProxySource("192.168.1.188","3128");
		s24.sign(fileToSign, targetFilepParallelHash);
		*/
		//#########################
		// XADES EXAMPLE
		//########################	
		/*
		//TEST XADES FIRMA PARALLLELA	
		SignUtilsDSS s15 = new SignUtilsDSS(SignatureLevel.XAdES_BASELINE_B,"JKS",false,false,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileXadesToSign.toPath()));
		s15.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"");
		s15.setTSPSource(TSP_SERVER_DEFAULT, null, null,DigestAlgorithm.SHA256,null,null,null);
		s15.setProxySource("192.168.1.188","3128");
		s15.sign(fileXadesToSign, fileXadesParallel);
		//TEST XADES FIRMA COUNTER
		SignUtilsDSS s16 = new SignUtilsDSS(SignatureLevel.XAdES_BASELINE_B,"JKS",false,false,true,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileXadesParallel.toPath()));
		s16.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s16.setTSPSource(TSP_SERVER_DEFAULT, null, null,DigestAlgorithm.SHA256,null,null,null);
		s16.setProxySource("192.168.1.188","3128");
		s16.sign(fileXadesParallel, fileXadesCounter);
		//TEST XADES FIRMA NESTED	
		SignUtilsDSS s17 = new SignUtilsDSS(SignatureLevel.XAdES_BASELINE_B,"JKS",false,true,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s17.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s17.setTSPSource(TSP_SERVER_DEFAULT, null, null,DigestAlgorithm.SHA256,null,"GET",null);
		s17.setProxySource("192.168.1.188","3128");
		s17.sign(fileXadesParallel,fileXadesNested);
		*/
		//#########################
		// PADES EXAMPLE
		//########################	
		/*		  
		//TEST PADES (BES) LA BASIC NON E' PIU' SUPPORTATA O ALMENO E? SCONSIGLIATA
		SignUtilsDSS s18 = new SignUtilsDSS(SignatureLevel.PAdES_BASELINE_B,"JKS",false,false,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s18.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s18.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		s18.setProxySource("192.168.1.188","3128");
		s18.sign(filePadesToSign, filePadesParallel);
		
		SignUtilsDSS s19 = new SignUtilsDSS(SignatureLevel.PAdES_BASELINE_B,"JKS",false,false,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s19.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s19.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		s19.setProxySource("192.168.1.188","3128");
		s19.sign(filePadesParallel, filePadesParallel2);
		*/
		
		//TEST PADES SOLO HASH FIRMA PARALLLELA
		SignUtilsDSS s20 = new SignUtilsDSS(SignatureLevel.PAdES_BASELINE_B,"JKS",false,false,false,false,false,false,false,SigningOperation.SIGN,Files.readAllBytes(fileToSign.toPath()));
		s20.setKeyStoreSource(keyStoreFile, keyStoreType, keyStorePassword,"testFirma");
		s20.setTSPSource(TSP_SERVER_COMODOCA, null, null,DigestAlgorithm.SHA1,null,"GET",null);
		//s20.setProxySource("192.168.1.188","3128");
		s20.sign(filePadesToSign, filePadesParallelHash);
	}

}
