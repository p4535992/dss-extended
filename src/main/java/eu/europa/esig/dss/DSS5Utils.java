package eu.europa.esig.dss;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureTokenType;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineLT;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineLTA;
import eu.europa.esig.dss.cades.signature.CAdESLevelBaselineT;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.cades.signature.CustomContentSigner;
import eu.europa.esig.dss.client.NonceSource;
import eu.europa.esig.dss.client.SecureRandomNonceSource;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader.HttpMethod;
import eu.europa.esig.dss.client.http.Protocol;
import eu.europa.esig.dss.client.http.ProxyNativeHTTPDataLoader;
import eu.europa.esig.dss.client.http.TspHTTPDataLoader;
import eu.europa.esig.dss.client.http.TspHTTPDataLoader.HttpProtocol;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.cookbook.mock.MockServiceInfo;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.token.mocca.MOCCASignatureTokenConnection;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignatureValidationContext;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonCertificateSource;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.OfflineCRLSource;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

public class DSS5Utils {

	private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DSS5Utils.class);
	
	 /*
     * Object identifier for the timestamping key purpose.
     */
    private static final String KP_TIMESTAMPING_OID = "1.3.6.1.5.5.7.3.8";

    /*
     * Object identifier for extendedKeyUsage extension
     */
    private static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";
	
	/**
     * Create the token connection.
     * Part of this code has been taken from {@link eu.europa.ec.markt.dss.applet.wizard.signature.CertificateStep#init()}.
     * @return the {@link SignatureTokenConnection} created, if any
     * @throws KeyStoreException In case of errors accessing the keystore
	 * @throws IOException 
     */
    public static SignatureTokenConnection prepareTokenConnection(File keystoreFile, SignatureTokenType signatureTokenType,String keystorePassword) throws KeyStoreException, IOException {
        PasswordInputCallback passwordInput = new MyPasswordStoredCallback(keystorePassword);
        char[] password = passwordInput.getPassword();
        SignatureTokenConnection connection;
        
        switch (signatureTokenType) {
            case MSCAPI: {
                connection = new MSCAPISignatureToken();
                break;
            }
            case MOCCA: {
                //connection = new MOCCAAdapter().createSignatureToken(passwordInput);
            	connection = new MOCCASignatureTokenConnection(passwordInput);
                break;
            }
            case PKCS11:
                connection = new Pkcs11SignatureToken(keystoreFile.getAbsolutePath(), password);
                break;
            case PKCS12:
                connection = new Pkcs12SignatureToken(keystoreFile,keystorePassword);
                break; 
            default:
            	//JKS
            	//connection = new JKSSignatureToken(keystoreFile.getAbsolutePath(), keystorePassword);               
            	throw new RuntimeException("No token connection selected");
        }
        //List<DSSPrivateKeyEntry> privateKeys = connection.getKeys();
        return connection;
    }
    
    public static SignatureTokenConnection prepareTokenConnection(File keystoreFile, String signatureTokenType,String keystorePassword) throws KeyStoreException, URISyntaxException, IOException {
        PasswordInputCallback passwordInput = new MyPasswordStoredCallback(keystorePassword);
        char[] password = passwordInput.getPassword();
        SignatureTokenConnection connection;

        switch (signatureTokenType) {
            case "MSCAPI": {
                connection = new MSCAPISignatureToken();
                break;
            }
            case "MOCCA": {
                //connection = new MOCCAAdapter().createSignatureToken(passwordInput);
            	connection = new MOCCASignatureTokenConnection(passwordInput);
                break;
            }
            case "PKCS11":
                connection = new Pkcs11SignatureToken(keystoreFile.getAbsolutePath(), password);
                break;
            case "PKCS12":
                //connection = new Pkcs12SignatureToken(password, keystoreFile);
            	connection = new Pkcs12SignatureToken(keystoreFile,keystorePassword);
                break;
            case "JKS":
            	connection = new JKSSignatureToken(keystoreFile, keystorePassword);              
            	break;           	
            default:
            	throw new RuntimeException("No token connection selected");
        }
        //List<DSSPrivateKeyEntry> privateKeys = connection.getKeys();
        return connection;
    }
       
    public static class XmlNullResolver implements EntityResolver {
  	  public InputSource resolveEntity(String publicId, String systemId) throws SAXException,
  	      IOException {
  	    return new InputSource(new StringReader(""));
  	  }
  	}
    
    /**
     * Set the default chooser object for the private key.
     *
     * @param builder The signature builder
     * @throws KeyStoreException 
     */
    public static DSSPrivateKeyEntry preparePrivateKeyChooser(SignatureTokenConnection signatureTokenConnection,String keystoreCN) throws KeyStoreException {
    	List<DSSPrivateKeyEntry> keys = prepareListDSSPrivateKeyEntry(signatureTokenConnection.getKeys());    	
        if (keystoreCN == null || keystoreCN.isEmpty()) {
            return new InputDSSPrivateKeyChooser().getDSSPrivateKey(keys);
        } else {
        	return new RegexDSSPrivateKeyChooser(keystoreCN).getDSSPrivateKey(keys);
        }
    }
    
    public static List<DSSPrivateKeyEntry> prepareListDSSPrivateKeyEntry(List<DSSPrivateKeyEntry> privateKeys){
    	List<DSSPrivateKeyEntry> filterkeys = new ArrayList<>();
    	for (DSSPrivateKeyEntry curKey : privateKeys) {
             if(curKey != null && curKey.getCertificate()!=null && curKey.getCertificate().getCertificate()!=null){
            	 filterkeys.add(curKey);
             }
             
        }
    	if(filterkeys!= null && filterkeys.isEmpty()){
	    	throw new DSSException("The keystore you try to use not have any private key to use for the signature");
	    }
    	return filterkeys;
    }
    
//    /**
//     * Get the subject DN {@link String} from a certificate.
//     * @param cert A {@link X509Certificate} to read the subject DN from
//     * @return The {@link String} representing the subject for the {@link X509Certificate}
//     */
//    public static String getSubjectDN(X509Certificate cert) {
//        String subjectDN = cert.getSubjectDN().getName();
//        int dnStartIndex = subjectDN.indexOf("CN=") + 3;
//        if (dnStartIndex > 0 && subjectDN.indexOf(",", dnStartIndex) > 0) {
//            subjectDN = subjectDN.substring(dnStartIndex, subjectDN.indexOf(",", dnStartIndex)) + " (SN:"
//                    + cert.getSerialNumber() + ")";
//        }
//        return subjectDN;
//    }
//    
//    public static String getSubjectDN(KeyStore keyStore,String alias) throws KeyStoreException {
//    	X509Certificate cert = ((X509Certificate)getCertificate(keyStore, alias));
//        String subjectDN = cert.getSubjectDN().getName();
//        int dnStartIndex = subjectDN.indexOf("CN=") + 3;
//        if (dnStartIndex > 0 && subjectDN.indexOf(",", dnStartIndex) > 0) {
//            subjectDN = subjectDN.substring(dnStartIndex, subjectDN.indexOf(",", dnStartIndex)) + " (SN:"
//                    + cert.getSerialNumber() + ")";
//        }
//        return subjectDN;
//    }
//
//    /**
//     * Get the issuer CN {@link String} from a certificate.
//     * @param cert A {@link X509Certificate} to read the issuer CN from
//     * @return The {@link String} representing the issuer CN for the {@link X509Certificate}
//     */
//    public static String getIssuerCN(X509Certificate cert) {
//        String issuerCN = cert.getIssuerDN().getName();
//        int cnStartIndex = issuerCN.indexOf("CN=") + 3;
//        if (cnStartIndex > 0 && issuerCN.indexOf(",", cnStartIndex) > 0) {
//            issuerCN = issuerCN.substring(cnStartIndex, issuerCN.indexOf(",", cnStartIndex));
//        }
//        return issuerCN;
//    }
//    
//    public static String getIssuerCN(KeyStore keyStore,String alias) throws KeyStoreException {
//    	X509Certificate cert = ((X509Certificate)getCertificate(keyStore, alias));
//        String issuerCN = cert.getIssuerDN().getName();
//        int cnStartIndex = issuerCN.indexOf("CN=") + 3;
//        if (cnStartIndex > 0 && issuerCN.indexOf(",", cnStartIndex) > 0) {
//            issuerCN = issuerCN.substring(cnStartIndex, issuerCN.indexOf(",", cnStartIndex));
//        }
//        return issuerCN;
//    }

    /**
     * Read an {@link Integer} from the standard input.
     * @return The read {@link Integer}
     * @throws IOException if a read error has occurred
     * @throws NumberFormatException if a parsing error has occurred
     */
    private static int readInt() throws IOException, NumberFormatException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        String input = bufferedReader.readLine();
        return Integer.parseInt(input);
    }

    /**
     * Read an {@link Integer} from the standard input, and ask again until the parsing succeeds.
     * @param maxAttempts Number of maximum attempts for reading, unhandled if less than 1.
     * @param lBound Lower bound accepted for the integer number (included).
     * @param uBound Upper bound accepted for the integer number (included).
     * @return The read {@link Integer}
     */
    @SuppressWarnings("ConstantConditions")
    private static int readInt(int maxAttempts, int lBound, int uBound) {
        boolean parsed;
        int number = -1;
        int attempt = 0;
        do {
            if (attempt > 0) {
                System.out.println("Not a valid selection. Please try again.");
            }
            try {
                attempt++;
                number = readInt();
                parsed = true;
            } catch (IOException e) {
                parsed = false;
            } catch (NumberFormatException e) {
                parsed = false;
            }                                                   // Repeat if...
        } while (!parsed ||                                     // - the number is not parsed
                (attempt < maxAttempts && maxAttempts >= 0) ||  // - maxAttempts not reached and must be accounted for
                (number < lBound) || (number > uBound));        // - the upper or lower bound is not respected

        return number;
    }

    /**
     * Get the file extension from a file name.
     * @param fileName The file name
     * @return The last extension for the file name
     */
    public static String prepareFileExtension(String fileName) {
        String extension = null;
        int i2 = fileName.lastIndexOf(".");
        if (i2 > 0) {
            extension = fileName.substring(i2);
        }
        return extension;
    }

    /**
     * Get the file name without the extension.
     * @param fileName The file name
     * @return The file name without the final extension
     */
    public static String prepareFileNameWithoutExtension(String fileName) {
        int i2 = fileName.lastIndexOf(".");
        String simpleFileName = null;
        if (i2 > 0) {
            // Get the original name without the extension
            simpleFileName = fileName.substring(0, i2);
        }
        return simpleFileName;
    }

    /**
     * Search a file in the resources, and return its absolute path if it exists,
     * otherwise return a null {@link String}.
     *
     * @param fileName The name of the file in the resources
     * @return The path {@link String} of the file, if any, or null
     */
    public static String prepareFileInResources(String fileName) {
        URL fileURL = DSS5Utils.class.getClassLoader().getResource(fileName);
        String filePath = null;
        if (fileURL != null) {
            filePath = fileURL.getFile();
        }
        return filePath;
    }

    /**
     * Search for a file in an absolute path, and always returns a {@link String},
     * even if the file does not exist.
     *
     * @param fileName The file absolute path
     * @return The path {@link String} of the file
     */
    public static String prepareFileInAbsolutePath(String fileName) {
        File file = new File(fileName);
        return file.getAbsolutePath();
    }

    /**
     * Search for a given file path:
     *  - handling the fileName as an absolute path
     *  - fallback in resources, returns it if it exists
     *
     * @param fileName File name or path of a file in resources or an absolute path
     * @return  The file absolute path as a {@link String}, if it was found anywhere
     *          in the absolute path or in the resources
     */
    public static String prepareFileInAbsolutePathOrResources(String fileName) throws FileNotFoundException {
        File file = new File(fileName);
        String filePath = file.getAbsolutePath();
        if (!file.exists()) {
             filePath = prepareFileInResources(fileName);
        }
        return filePath;
    }
    
//    /**
//     * Get the suggested target file name.
//     * This method is a wrapper around the original {@link it.latraccia.dss.util.builder.SignatureBuilder#prepareTargetFileName(java.io.File,
//     * eu.europa.ec.markt.dss.signature.SignaturePackaging, String)}.
//     *
//     * @return The suggested target file name
//     */
//    public static String prepareSuggestedFileName(File sourceFile,SignaturePackaging signaturePackaging,String signatureFormat) {
//    	return prepareTargetFileName(
//                sourceFile,signaturePackaging,signatureFormat).getName();
//    }

//    /**
//     * Suggest the target file name.
//     * Original code in {@link eu.europa.ec.markt.dss.applet.wizard.signature.SaveStep#prepareTargetFileName(java.io.File,
//     * eu.europa.ec.markt.dss.signature.SignaturePackaging, String)}
//     *
//     * @param file               The selected file to sign
//     * @param signaturePackaging The selected packaging
//     * @param signatureFormat    The complete signature format (e.g. "CAdES")
//     * @return The suggested target File
//     */
//    public static File prepareTargetFileName(final File file,
//                                       final SignaturePackaging signaturePackaging,
//                                       final String signatureFormat) {
//
//        final File parentDir = file.getParentFile();
//        final String originalName = StringUtils.substringBeforeLast(file.getName(), ".");
//        final String originalExtension = "." + StringUtils.substringAfterLast(file.getName(), ".");
//        final String format = signatureFormat.toUpperCase();
//        
//        if ((SignaturePackaging.ENVELOPING == signaturePackaging || SignaturePackaging.DETACHED == signaturePackaging) && format.startsWith("XADES")) {
//            return new File(parentDir, originalName + "-signed" + ".xml");
//        }
//
//        if (format.startsWith("CADES") && !originalExtension.toLowerCase().equals(".p7m")) {
//            return new File(parentDir, originalName + originalExtension + ".p7m");
//        }
//
//        if (format.startsWith("ASIC")) {
//            return new File(parentDir, originalName + originalExtension + ".asics");
//        }
//
//        return new File(parentDir, originalName + "-signed" + originalExtension);
//
//    }
    
    public static String prepareTargetFileName(String sourceName,SignatureLevel signatureLevel,
    		boolean returnFullPath,boolean isCounterSignature , boolean isExtended, boolean isParallel,boolean isOnlyMark){
    	String ext = FilenameUtils.getExtension(sourceName);
		String newExt = "";
		if(ext.equalsIgnoreCase("p7m")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}
			else if(isOnlyMark){
				newExt = ".tsr";
			}
			else{newExt = ".p7m";}
		}
		else if(ext.equalsIgnoreCase("p7s")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}
			else if(isOnlyMark){
				newExt = ".tsr";
			}
			else{newExt = ".p7s";}
		}
		else  if(ext.equalsIgnoreCase("p7s")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}
			else if(isOnlyMark){
				newExt = ".tsr";
			}
			else{newExt = ".p7s";}
		}
		else  if(ext.equalsIgnoreCase("m7m")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}
			else if(isOnlyMark){
				newExt = ".tsr";
			}
			else{newExt = ".m7m";}
		}
		else  if(ext.equalsIgnoreCase("tsr")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}			
			else{newExt = ".tsr";}
		}
		else  if(ext.equalsIgnoreCase("tsd")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}
			else if(isOnlyMark){
				newExt = ".tsr";
			}
			else{newExt = ".tsd";}
		}
		else  if(ext.equalsIgnoreCase("pdf")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}
			else if(isOnlyMark){
				newExt = ".tsr";
			}
			else{
				if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
					newExt = ".p7m";
				}else if(signatureLevel.getSignatureForm().equals(SignatureForm.PAdES)){
					newExt = "";
				}
			}
		}
		else  if(ext.equalsIgnoreCase("xml")){
			if(isCounterSignature || isExtended || isParallel){newExt = "";}
			else if(isOnlyMark){
				newExt = ".tsr";
			}
			else{
				if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
					newExt = ".p7m";
				}else if(signatureLevel.getSignatureForm().equals(SignatureForm.XAdES)){
					newExt = "";
				}
			}
		}else {
			if(isOnlyMark){
				newExt = ".tsr";
			}
		    else if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
				newExt = ".p7m";
			}
			else {
				newExt = "";
			}
		}
		//DSSUtils.getFinalFileName(originalFile, operation, level)
		if(returnFullPath){
			return FilenameUtils.getFullPath(sourceName)+File.separator+FilenameUtils.getName(sourceName)+newExt;
		}else{
			return FilenameUtils.getName(sourceName)+newExt;
		}
    }
    
    /**
     * Simple key chooser handler, asks the user for a selection.
     */
    public static class InputDSSPrivateKeyChooser implements IDSSPrivateKeyChooser {
    	
    	private org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(InputDSSPrivateKeyChooser.class);
    	
        @Override
        public DSSPrivateKeyEntry getDSSPrivateKey(List<DSSPrivateKeyEntry> keys) {
            DSSPrivateKeyEntry key = null;
            if (keys != null) {
                if (keys.size() > 1) {
                    // Print the choices
                	logger.debug("The following keys have been found:");
                    int i = 1;
                    List<DSSPrivateKeyEntry> keys2 = new ArrayList<>();
                    for (DSSPrivateKeyEntry k : keys) {
                    	if(k != null){
	                    	if(k.getCertificate()!=null){
		                        String subject = CertificateUtils.getSubjectDN(k.getCertificate().getCertificate());
		                        logger.debug(String.format("[%d] %s", i++, subject));
		                        keys2.add(k);
	                    	}
                    	}
                    }

                    // Ask for a choice
                    int keyIndex;
                    logger.debug("Select the number of the certificate you wish to use:");

                    if(keys2.size() > 1){
	                    // Read the integer until we get a valid number within the entries' bounds
	                    keyIndex = readInt(-1, 1, keys.size());
	                    // Get the key and print a summary
	                    key = keys.get(keyIndex - 1);
                    }else{
                    	key = keys.get(0);
                    }
                    logger.debug(String.format("Certificate selected: %s",CertificateUtils.getSubjectDN(key.getCertificate().getCertificate())));
                } else {
                    // Use the first one
                    key = keys.get(0);
                }
            }
            return key;
        }
    }

    /**
     * Choose a key by matching the issuer CN against a regex of acceptable ones.
     * Only the first accepted key will be returned
     */
    public static class RegexDSSPrivateKeyChooser implements IDSSPrivateKeyChooser {
    	
    	private org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RegexDSSPrivateKeyChooser.class);
    	
        private String regexIssuerCN;

        public RegexDSSPrivateKeyChooser(String issuerCN) {
            regexIssuerCN = issuerCN;
        }

        @Override
        public DSSPrivateKeyEntry getDSSPrivateKey(List<DSSPrivateKeyEntry> keys) {
            DSSPrivateKeyEntry key = null;
            if (keys != null) {
                // for each string to match
                // return the first key that matches
                for (DSSPrivateKeyEntry curKey : keys) {
                    String issuerCN = CertificateUtils.getIssuerCN(curKey.getCertificate().getCertificate());
                    if (issuerCN.matches(regexIssuerCN)) {
                        key = curKey;
                        break;
                    }
                }
            }
            return key;
        }
    }
    
    /**
     * Return a previously-read password already stored in the model.
     */
    private static class MyPasswordStoredCallback implements PasswordInputCallback {
        
    	private String keyStorePassword;
    	
    	public MyPasswordStoredCallback(String keyStorePassword){
    		this.keyStorePassword=keyStorePassword;
    	}
    	
    	public char[] getPassword() {
            return keyStorePassword.toCharArray();
        }
    }

    public interface IDSSPrivateKeyChooser {
        public DSSPrivateKeyEntry getDSSPrivateKey(List<DSSPrivateKeyEntry> keys);
    }
    
    public static CRLSource prepareOnlineCRLSource(String serviceUrl) {
		OnlineCRLSource crlSource = new OnlineCRLSource();
		CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
		crlSource.setDataLoader(commonsDataLoader);
		//crlSource.setDataLoader(new NativeHTTPDataLoader());
		crlSource.setPreferredProtocol(Protocol.HTTP);
		return crlSource;
	}
    
    public static CRLSource prepareOfflineCRLSource(X509Certificate x509Certificate) {
    	CertificateToken certificateToken = new CertificateToken(x509Certificate);
		OfflineCRLSource crlSource = new OfflineCRLSource() {
			/**
			 * 
			 */
			private static final long serialVersionUID = 1L;
		};
		crlSource.findCrl(certificateToken);
		return crlSource;
	}

	public static OCSPSource prepareOnlineOCSPSource(String serviceUrl) {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		//ocspSource.setUrl(getServiceURL() + OCSP_CONTEXT);
		//ocspSource.setUrl(serviceUrl);
		ocspSource.setDataLoader(new NativeHTTPDataLoader());
		return ocspSource;
	}

//	public static CertificateSource prepareRemoteCertificateSource(CertificateSource certificateSource) {
//		final OnlineCertificateSource tslCertSource = new CommonCertificateSource();
//		tslCertSource.setDelegate(certificateSource);
//		return tslCertSource;
//	}
	
	public static CertificateSource prepareKeystoreCertificateSource(File keyStoreFile,String keyStoreType, String keyStorePassword) throws IOException {
		KeyStoreCertificateSource k = 
				new KeyStoreCertificateSource(keyStoreFile,keyStoreType, keyStorePassword);
		return k;
	}
	
	public static CertificateSource prepareSimpleCertificateSource(Certificate certificate) {
		CommonCertificateSource s = 
				new CommonCertificateSource();
		s.addCertificate(new CertificateToken((X509Certificate)certificate));
		return s;
	}

	public static CertificateVerifier prepareCertificateVerifier(CRLSource crlSource, OCSPSource ocspSource,CertificateSource certificatesSource) {
		CommonCertificateVerifier  certificateVerifier = 
				new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(crlSource);
		certificateVerifier.setOcspSource(ocspSource);
		certificateVerifier.setTrustedCertSource(certificatesSource);
		return certificateVerifier;
	}
	
	public static CertificateVerifier prepareCertificateVerifier(CertificateSource certificatesSource) {
		CommonCertificateVerifier certificateVerifier = 
				new CommonCertificateVerifier();		
		certificateVerifier.setTrustedCertSource(certificatesSource);
		return certificateVerifier;
	}
	
//	public static TSPSource prepareRemoteTSPSource(String tspServer) {
//		final TSPSource remoteTSPSource = new R;
//		//remoteTSPSource.setUrl(getServiceURL() + TSP_CONTEXT);
//		remoteTSPSource.setUrl(tspServer);
//		remoteTSPSource.setDataLoader(new NativeHTTPDataLoader());
//		return remoteTSPSource;
//	}
	
//	public static TSPSource prepareOnlineTSPSource(String tspServer) {
//		//Set the Timestamp source		
//		OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);
//		return onlineTSPSource;
//	}
	
	public static TSPSource prepareOnlineTSPSource(TimeStamper timeStamper,byte[] toDigest) throws DSSException, NumberFormatException, IOException, TSPException{		
		String tspServer = timeStamper.getTsaUrl().toString();
		String policyOid = timeStamper.getPolicyOid().toString();
		//NonceSource nonceSource = new SecureRandomNonceSource();
		NonceSource nonceSource =  timeStamper.getNonceSource();
		DigestAlgorithm digestAlgorithm = timeStamper.getDigestAlgorithm();//DigestAlgorithm.forOID(String.valueOf(timeStamper.getMessageDigest()[1]));
		if(digestAlgorithm == null)digestAlgorithm = DigestAlgorithm.SHA256;
		TimestampDataLoader tspDataLoader = timeStamper.timestampDataLoader();
		//Start prepare tspdataloader
		/*
		int tspPort = timeStamper.getTsaPort();
		String tspUsername = timeStamper.getTsaUsername();
		String tspPassword = timeStamper.getTsaPassword();
		String tspScheme = timeStamper.getTsaScheme();
		
		String httpMethod = timeStamper.getRequestMethod();
		//Proxy proxy = timeStamper.getProxy();
		ProxyConfig proxyConfig = timeStamper.getProxyConfig();
		DigestAlgorithm digestAlgorithm = timeStamper.getDigestAlgorithm();//DigestAlgorithm.forOID(String.valueOf(timeStamper.getMessageDigest()[1]));
		ASN1ObjectIdentifier tspaAlgorithm = timeStamper.getTspaAlgorithm();
		String requestMethod = timeStamper.getRequestMethod();	
		NonceSource nonceSource = timeStamper.getNonceSource();	
		TimestampDataLoader tspDataLoader =  new TimestampDataLoader();//Mange request to TSP server with a proxy		
		if(proxyConfig != null){
			tspDataLoader.setProxyConfig(proxyConfig);
		}
		if(timeStamper.getTsaUsername() != null && !timeStamper.getTsaUsername().isEmpty() &&
				timeStamper.getTsaPassword()!= null && !timeStamper.getTsaPassword().isEmpty()){
			tspDataLoader.addAuthentication(tspServer, tspPort, tspScheme, tspUsername,tspPassword);
		}
		*/

		OnlineTSPSource tspSource = new OnlineTSPSource();		
		tspSource.setPolicyOid(policyOid);
		tspSource.setTspServer(tspServer);	
		try {	
			//Check the correct creation of the token
			 prepareTimeStampResponse(tspServer, toDigest, tspDataLoader, digestAlgorithm, nonceSource, policyOid);
			 if(nonceSource !=null){
				 tspSource.setNonceSource(nonceSource);
			 }
			 tspSource.setDataLoader(tspDataLoader);
			 return tspSource;
		} catch (TSPException e) {
			throw new DSSException("Invalid TSP response", e);
		} catch (IOException e) {
			throw new DSSException(e);
		}	
	    //return prepareOnlineTSPSource(tspServer,toDigest,digestAlgorithm,null,null,proxy,policyOid,httpMethod,nonceSource);
	}
	
//	@Deprecated
//	public static TSPSource prepareOnlineTSPSource(String tspServer,byte[] toDigest,DigestAlgorithm digestAlgorithm,String tspUsername,String tspPassword,NonceSource nonceSource) throws KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException{
//		return prepareOnlineTSPSource(tspServer,toDigest,digestAlgorithm,tspUsername,tspPassword,null,null,"POST",nonceSource);
//	}
//		
//	@Deprecated
//	public static TSPSource prepareOnlineTSPSource(String tspServer,byte[] toDigest,DigestAlgorithm digestAlgorithm,String tspUsername,String tspPassword,String proxyHost,String proxyPort,final String proxyUsername,final String proxyPassword,String policyOid,
//			String httpMethod,NonceSource nonceSource) throws DSSException, NumberFormatException, UnknownHostException{
//		Proxy proxy = null;
//		if (proxyHost != null && !proxyHost.isEmpty() && proxyPort== null && !proxyPort.isEmpty()) {
//			proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, Integer.valueOf(proxyPort)));
//            if (StringUtils.isNotEmpty(proxyUsername) && StringUtils.isNotEmpty(proxyPassword))
//            {
//                // Set default authentication
//                Authenticator.setDefault(new Authenticator()
//                {
//                    @Override
//                    public PasswordAuthentication getPasswordAuthentication()
//                    {
//                        return new PasswordAuthentication(proxyUsername, proxyPassword.toCharArray());
//                    }
//                });
//            }
//		}
//		return prepareOnlineTSPSource(tspServer,toDigest,digestAlgorithm,tspUsername,tspPassword,proxy,policyOid,httpMethod,nonceSource);
//	}
//	
//	@Deprecated
//	private static TSPSource prepareOnlineTSPSource(String tspServer,byte[] toDigest,DigestAlgorithm digestAlgorithm,String tspUsername,String tspPassword,Proxy proxy,String policyOid,
//			String httpMethod,NonceSource nonceSource) throws DSSException, NumberFormatException, UnknownHostException{
//		OnlineTSPSource tspSource = new OnlineTSPSource();		
//		tspSource.setPolicyOid(policyOid);
//		tspSource.setTspServer(tspServer);		
//		DataLoader dataLoader = null;
//		if (proxy != null) {
//			dataLoader =  new TspHTTPDataLoader(proxy);//Mange request to TSP server with a proxy
//		}else{
//			dataLoader = new TspHTTPDataLoader();
//		}
//		((TspHTTPDataLoader)dataLoader).setHttpMethod(httpMethod);
//		((TspHTTPDataLoader)dataLoader).setHttpProtocol(HttpProtocol.HTTP);
//		tspSource.setDataLoader(dataLoader);
//
//		if(digestAlgorithm == null)digestAlgorithm = DigestAlgorithm.SHA256;
//
//		//NonceSource nonceSource = new SecureRandomNonceSource();
//		if(nonceSource!=null)tspSource.setNonceSource(nonceSource);	
//		//final byte[] digestValue = toDigest;				
//		//final TimeStampToken tsr = tspSource.getTimeStampResponse(digestAlgorithm,digestValue);		
//		//logger.debug(DSSUtils.toHex(tsr.getEncoded()));	
//		try {	
//			/*
//			//final byte[] toDigest = "digest value".getBytes("UTF-8");
//			final byte[] digest = digest(digestAlgorithm, toDigest);	
//			logger.debug("Timestamp digest algorithm: " + digestAlgorithm.getName());
//			logger.debug("Timestamp digest value    : " + Utils.toHex(digest));
//			// Setup the time stamp request
//			final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
//			tsqGenerator.setCertReq(true);
//			if (policyOid != null) {
//				tsqGenerator.setReqPolicy(policyOid);
//			}
//			ASN1ObjectIdentifier tspaAlgorithm = new ASN1ObjectIdentifier(digestAlgorithm.getOid());
//			TimeStampRequest timeStampRequest = null;
//			if (nonceSource == null) {
//				timeStampRequest = tsqGenerator.generate(tspaAlgorithm, digest);
//			} else {				
//				timeStampRequest = tsqGenerator.generate(tspaAlgorithm, digest, nonceSource.getNonce());
//			}			
//			final byte[] requestBytes = timeStampRequest.getEncoded();
//			// Handle the TSA response
//			byte[] respBytes =  null;
//			//if(httpMethod==HttpMethod.POST){				
//			//	respBytes = dataLoader.post(tspServer, requestBytes);
//			//}else{
//			//	respBytes = dataLoader.get(tspServer, requestBytes,true,HttpProtocol.HTTP);
//			//}	
//			if (dataLoader == null) {
//				dataLoader = new NativeHTTPDataLoader();
//			}
//			respBytes = dataLoader.post(tspServer, requestBytes);			
//	        logger.debug("Response TSP : " + Arrays.toString(respBytes));
//			TimeStampResponse timeStampResponse = new TimeStampResponse(respBytes);				
//			//final TimeStampResponse timeStampResponse = getTimeStampResponseCustom(tspServer,digestAlgorithm, digest,username,password,policyOid,proxyHost,proxyPort);
//			// Validates token, nonce, policy id, message digest ...
//			timeStampResponse.validate(timeStampRequest);
//			String statusString = timeStampResponse.getStatusString();
//			if (statusString != null) {
//				logger.info("Status: " + statusString);
//			}
//			PKIFailureInfo failInfo = timeStampResponse.getFailInfo();
//			if (failInfo != null) {
//				logger.warn("TSP Failure info: " + failInfo.toString());
//			}
//			final TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
//			if (timeStampToken != null) {
//				logger.info("TSP SID : SN " + timeStampToken.getSID().getSerialNumber() + ", Issuer " + timeStampToken.getSID().getIssuer());
//			}
//			*/
//			prepareTimeStampResponse(tspServer, toDigest, dataLoader, digestAlgorithm, nonceSource, policyOid);
//		} catch (TSPException e) {
//			throw new DSSException("Invalid TSP response", e);
//		} catch (IOException e) {
//			throw new DSSException(e);
//		}
//		//final org.bouncycastle.tsp.TimeStampResponse tsr = getTimeStampResponseCustom(tspServer,digestAlgorithm, digest,username,password,null,proxyHost,proxyPort);
//		//logger.debug(DSSUtils.toHex(tsr.getEncoded()));				
//		return tspSource;
//	}
//	
	
	/**
	 * Method to retrieve the response token of a tsp service
	 */
	public static TimeStampResponse prepareTimeStampResponse(TimeStamper timeStamper,byte[] toDigest) throws IOException, TSPException{	
		String tspServer = timeStamper.getTsaUrl().toString();
		String policyOid = timeStamper.getPolicyOid().toString();		
		DigestAlgorithm digestAlgorithm = timeStamper.getDigestAlgorithm();
		NonceSource nonceSource = timeStamper.getNonceSource();
		DataLoader dataLoader = timeStamper.timestampDataLoader();
		if(digestAlgorithm == null)digestAlgorithm = DigestAlgorithm.SHA256;	
		try {	
			return prepareTimeStampResponse(tspServer, toDigest, dataLoader, digestAlgorithm, nonceSource, policyOid);
		} catch (TSPException e) {
			throw new DSSException("Invalid TSP response", e);
		} catch (IOException e) {
			throw new DSSException(e);
		}		
	}

	/**
	 * Method to verify the response token of a tsp service
	 */
	private static TimeStampResponse prepareTimeStampResponse(String tspServer,byte[] toDigest,DataLoader dataLoader,DigestAlgorithm digestAlgorithm,NonceSource nonceSource,String policyOid) throws IOException, TSPException{	
		try {
			final byte[] digest = digest(digestAlgorithm, toDigest);	
			logger.debug("Timestamp digest algorithm: " + digestAlgorithm.getName());
			logger.debug("Timestamp digest value    : " + Utils.toHex(digest));
			// Setup the time stamp request
			final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
			tsqGenerator.setCertReq(true);
			if (policyOid != null) {
				tsqGenerator.setReqPolicy(policyOid);
			}
			ASN1ObjectIdentifier tspaAlgorithm = new ASN1ObjectIdentifier(digestAlgorithm.getOid());
			TimeStampRequest timeStampRequest = null;
			if (nonceSource == null) {
				timeStampRequest = tsqGenerator.generate(tspaAlgorithm, digest);
			} else {				
				timeStampRequest = tsqGenerator.generate(tspaAlgorithm, digest, nonceSource.getNonce());
			}			
			final byte[] requestBytes = timeStampRequest.getEncoded();
			// Handle the TSA response
			byte[] respBytes =  null;
//			if(httpMethod==HttpMethod.POST){				
//				respBytes = dataLoader.post(tspServer, requestBytes);
//			}else{
//				respBytes = dataLoader.get(tspServer, requestBytes,true,HttpProtocol.HTTP);
//			}	
			if (dataLoader == null) {
				dataLoader = new NativeHTTPDataLoader();
			}
			respBytes = dataLoader.post(tspServer, requestBytes);			
	        logger.debug("Response TSP : " + Arrays.toString(respBytes));
			TimeStampResponse timeStampResponse = new TimeStampResponse(respBytes);				
			//final TimeStampResponse timeStampResponse = getTimeStampResponseCustom(tspServer,digestAlgorithm, digest,username,password,policyOid,proxyHost,proxyPort);
			// Validates token, nonce, policy id, message digest ...
			timeStampResponse.validate(timeStampRequest);
			String statusString = timeStampResponse.getStatusString();
			if (statusString != null) {
				logger.info("Status: " + statusString);
			}
			PKIFailureInfo failInfo = timeStampResponse.getFailInfo();
			if (failInfo != null) {
				logger.warn("TSP Failure info: " + failInfo.toString());
			}
			final TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
			if (timeStampToken != null) {
				logger.info("TSP SID : SN " + timeStampToken.getSID().getSerialNumber() + ", Issuer " + timeStampToken.getSID().getIssuer());
			}
			return timeStampResponse;
		} catch (TSPException e) {
			throw new DSSException("Invalid TSP response", e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
			
	}
	
//	@Deprecated
//	public static TimeStampResponse prepareTimeStampResponse(String tspServer,byte[] toDigest,String username,String password,String proxyHost,String proxyPort) throws IOException, KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException{
//		final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
//		final byte[] digestValue = digest(digestAlgorithm, toDigest);
//		final org.bouncycastle.tsp.TimeStampResponse tsr = prepareTimeStampResponseCustom(tspServer,digestAlgorithm, digestValue,username,password,null,proxyHost,proxyPort);
//		logger.debug(DSSUtils.toHex(tsr.getEncoded()));		
//		return tsr;
//	}
	/*
	private static byte[] generateTimestampToken(Timestamper tsa,
	        String tSAPolicyID, byte[] toBeTimestamped) throws IOException,
	        CertificateException {
	    // Generate a timestamp
	    MessageDigest messageDigest = null;
	    TSRequest tsQuery = null;
	    try {
	        // SHA-1 is always used.
	        messageDigest = MessageDigest.getInstance("SHA-1");
	        tsQuery = new TSRequest(tSAPolicyID, toBeTimestamped,
	                messageDigest);
	    } catch (NoSuchAlgorithmException e) {
	        // ignore
	    }

	    // Generate a nonce
	    BigInteger nonce = null;
	   
	    nonce = new BigInteger(64, new SecureRandom());
	    tsQuery.setNonce(nonce);
	    
	    tsQuery.requestCertificate(true);

	    TimeStampResponse tsReply = tsa.generateTimestamp(tsQuery);
	    int status = tsReply.getStatusString());
	    // Handle TSP error
	    if (status != 0 && status != 1) {
	        throw new IOException("Error generating timestamp: "
	                + tsReply.getStatusCodeAsText() + " "
	                + tsReply.getFailureCodeAsText());
	    }

	    if (tSAPolicyID != null
	            && !tSAPolicyID.equals(tsReply.getTimestampToken()
	                    .getPolicyID())) {
	        throw new IOException("TSAPolicyID changed in "
	                + "timestamp token");
	    }
	    TimestampToken tst = tsReply.getTimestampToken();
	    if (!tst.getSignatureAlgorithm()..equals("SHA-1")) {
	        throw new IOException("Digest algorithm not SHA-1 in "
	                + "timestamp token");
	    }
	    if (!MessageDigest.isEqual(tst.getHashedMessage(),
	            tsQuery.getHashedMessage())) {
	        throw new IOException(
	                "Digest octets changed in timestamp token");
	    }

	    BigInteger replyNonce = tst.getNonce();
	    if (replyNonce == null && nonce != null) {
	        throw new IOException("Nonce missing in timestamp token");
	    }
	    if (replyNonce != null && !replyNonce.equals(nonce)) {
	        throw new IOException("Nonce changed in timestamp token");
	    }

	    // Examine the TSA's certificate (if present)
	    for (SignerInfo si : tsToken.getSignerInfos()) {
	        X509Certificate cert = si.getCertificate(tsToken);
	        if (cert == null) {
	            // Error, we've already set tsRequestCertificate = true
	            throw new CertificateException(
	                    "Certificate not included in timestamp token");
	        } else {
	            if (!cert.getCriticalExtensionOIDs().contains(EXTENDED_KEY_USAGE_OID)) {
	                throw new CertificateException(
	                        "Certificate is not valid for timestamping");
	            }
	            List<String> keyPurposes = cert.getExtendedKeyUsage();
	            if (keyPurposes == null
	                    || !keyPurposes.contains(KP_TIMESTAMPING_OID)) {
	                throw new CertificateException(
	                        "Certificate is not valid for timestamping");
	            }
	        }
	    }
	    return tsReply.getEncodedToken();
	}
	*/
	
//	@Deprecated
//	public static TimeStampResponse prepareTimeStampResponseCustom(String tspServer,DigestAlgorithm digestAlgorithm, byte[] digest,String proxyHost,String proxyPort) throws IOException, KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
//		return prepareTimeStampResponseCustom(tspServer, digestAlgorithm, digest, null, null,null,proxyHost,proxyPort);
//	}
	
//	@Deprecated
//	public static TimeStampResponse prepareTimeStampResponseCustom(String tspServer,DigestAlgorithm digestAlgorithm, byte[] digest,String username,String password,String policyOid,String proxyHost,String proxyPort) throws IOException, KeyManagementException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
//      try {
//         byte[] respBytes = null;
//
//         // Setup the time stamp request
//         TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
//         tsqGenerator.setCertReq(true);
//         if (policyOid != null) {
//            tsqGenerator.setReqPolicy(new ASN1ObjectIdentifier(policyOid));
//         }
//         TimeStampRequest request = tsqGenerator.generate(digestAlgorithm.getOid(), new byte[20], BigInteger.valueOf(100));
//         byte[] requestBytes = request.getEncoded();
//
//         // Call the communications layer
//         respBytes = prepareTimeStampResponseCustom42(tspServer,requestBytes,username,password,proxyHost,proxyPort);
//
//         // Handle the TSA response
//         TimeStampResponse response = new TimeStampResponse(respBytes);
//         return response;
//
//      } catch (TSPException ex) {
//         throw new IOException("Invalid TSP response",ex);
//      }
//
//   }
	
	/**
     *Creates HTTP request and processes HTTP response.
     *https://www.ivankrizsan.se/2014/10/08/testing-https-connections-with-apache-httpclient-4-2/
    */	
	@Deprecated
   private static byte[] prepareTimeStampResponseCustom42(String tsaUri, byte[] tsr,String username,String password,String proxyHost,String proxyPort) throws ClientProtocolException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, KeyManagementException
   {
	 
	 // Load client truststore.
     //final KeyStore theClientTruststore = KeyStore.getInstance("JKS");
     //theClientTruststore.load(new FileInputStream(new File("C:\\Users\\Pancio\\Desktop\\test_firma\\testKeystore.jks")),"changeit".toCharArray());

     // Create a trust manager factory using the client truststore. 
     //final TrustManagerFactory theTrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
     //theTrustManagerFactory.init(theClientTruststore);

     //Create a SSL context with a trust manager that uses the client truststore.     
     final SSLContext theSslContext = SSLContext.getInstance("SSL");
     //theSslContext.init(null, theTrustManagerFactory.getTrustManagers(),null);
      
     // set up a TrustManager that trusts everything
     
     theSslContext.init(null, new TrustManager[] { new X509TrustManager() {
                 public X509Certificate[] getAcceptedIssuers() {return null;}
                 public void checkClientTrusted(X509Certificate[] certs,String authType) {}
                 public void checkServerTrusted(X509Certificate[] certs, String authType) {}
     } }, new SecureRandom());
	
     
     // Create a SSL socket factory that uses the client truststore SSL
     // context and that does not perform any kind of hostname verification.
     // IMPORTANT: Hostname verification should be performed in a
     // production environment!
     // To turn on hostname verification, change the
     // ALLOW_ALL_HOSTNAME_VERIFIER below to STRICT_HOSTNAME_VERIFIER.
      
     final SSLSocketFactory theSslSocketFactory = new SSLSocketFactory(theSslContext,SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
     //SSLSocketFactory sf = new SSLSocketFactory(sslContext);
     
     // Register the SSL socket factory to be used with HTTPS connections
     // with the HTTP client.
     // A {@code Scheme} object is used to associate the protocol scheme,
     // such as HTTPS in this case, and a socket factory.

     final Scheme theHttpsScheme = new Scheme("https", 443, theSslSocketFactory);
     // Scheme httpsScheme = new Scheme("https", 443, sf);
     
     SchemeRegistry schemeRegistry = new SchemeRegistry();
     schemeRegistry.register(theHttpsScheme);
     
     // SchemeRegistry schemeRegistry = new SchemeRegistry();
     //schemeRegistry.register(httpsScheme);
     // apache HttpClient version >4.2 should use BasicClientConnectionManager
     //ClientConnectionManager cm = new SingleClientConnManager(schemeRegistry);
     ClientConnectionManager cm = new BasicClientConnectionManager(schemeRegistry);
     
     //ClientConnectionManager ccm = base.getConnectionManager();
     //SchemeRegistry sr = ccm.getSchemeRegistry();
     //sr.register(new Scheme("https", 443, ssf));
      
     //HttpClient client =  new DefaultHttpClient(cm);
         
   	 HttpClient client = new DefaultHttpClient();
     client.getConnectionManager().getSchemeRegistry().register(theHttpsScheme);
     
     //SET PROXY
     if(proxyHost != null && !proxyHost.isEmpty() && proxyPort != null && !proxyPort.isEmpty()){
	     HttpHost proxy = new HttpHost(proxyHost,Integer.valueOf(proxyPort));
	     client.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY,proxy);
     }

   	 HttpPost httpPost = new HttpPost(tsaUri);
   	 byte[] bytes = null;
     List<NameValuePair> params = new ArrayList<NameValuePair>();
     if(username != null && !username.isEmpty())params.add(new BasicNameValuePair("username", username));
     if(password != null && !password.isEmpty())params.add(new BasicNameValuePair("password", password));
   	 httpPost.setEntity(new UrlEncodedFormEntity(params));
   	 httpPost.setHeader(HttpHeaders.CONTENT_TYPE,"application/timestamp-query");
   	 //httpReq.ContentLength = reqData.Length;
   	 
   	 int timeout = 50;
   	 HttpParams httpParams = client.getParams();
   	 HttpConnectionParams.setConnectionTimeout(httpParams, timeout * 1000); // http.connection.timeout
     HttpConnectionParams.setSoTimeout(httpParams, timeout * 1000); // http.socket.timeout
   	 
   	 HttpResponse response = client.execute(httpPost);
   	 if(response.getStatusLine().getStatusCode()==HttpStatus.SC_OK){
   		 ByteArrayOutputStream baos = new ByteArrayOutputStream();
   		 response.getEntity().writeTo(baos);
   		 bytes = baos.toByteArray();
   	 }else{
   		logger.debug("HTTP ERROR : " + String.valueOf(response.getStatusLine().getStatusCode()));
   		BufferedReader r = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
   		StringBuilder total = new StringBuilder();
   		String line = null;
   		while ((line = r.readLine()) != null) {
   		   total.append(line);
   		}
   		r.close();
   		logger.debug(total.toString());
   	 }
   	 HttpClientUtils.closeQuietly(client);
   	 return bytes;
   }

	//TODO implementare a mano per la vecchia versione
	/*
	public static TSPSource prepareMockTSPSource(){
		// Set the TimeStamp
		MockTSPSource mockTSPSource;
		try {
		        mockTSPSource = new MockTSPSource(new CertificateService().generateTspCertificate(SignatureAlgorithm.RSA_SHA256));
		        service.setTspSource(mockTSPSource);
		} catch (Exception e) {
		        throw new DSSException("Error during MockTspSource", e);
		}
	}
	*/
	
   @Deprecated
	public static CertificateSource prepareCertificateSource102853(String serviceUrl) {
		final TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
		//trustedListsCertificateSource.setDataLoader(new NativeHTTPDataLoader());
		//trustedListsCertificateSource.setServiceUrl(getServiceURL() + CERTIFICATE_CONTEXT);
		//trustedListsCertificateSource.setServiceUrl(serviceUrl);
		return trustedListsCertificateSource;
	}

	public static CommonCertificateVerifier prepareTrustedListCertificateVerifier102853(CRLSource crlSource, OCSPSource ocspSource,
			TrustedListsCertificateSource certificateSource) {
		final CommonCertificateVerifier trustedListCertificateVerifier = new CommonCertificateVerifier();
		trustedListCertificateVerifier.setCrlSource(crlSource);
		trustedListCertificateVerifier.setOcspSource(ocspSource);
		trustedListCertificateVerifier.setTrustedCertSource(certificateSource);
		return trustedListCertificateVerifier;
	}
	
	public static TrustedListsCertificateSource prepareTrustedCertificateSource(String certificatePath) {
		CommonCertificateSource adjunctCertificateSource = new CommonTrustedCertificateSource();
		CertificateToken intermediateCert = DSSUtils.loadCertificate(new File(certificatePath));//"/intermediate.cer"
		adjunctCertificateSource.addCertificate(intermediateCert);
		return  (TrustedListsCertificateSource) adjunctCertificateSource;
	}
	
	public static TrustedListsCertificateSource prepareTrustedCertificateSource(Certificate certificate) {
		CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
		//X509Certificate intermediateCert = DSSUtils.loadCertificate(certificate);//"/intermediate.cer"
		adjunctCertificateSource.addCertificate(new CertificateToken((X509Certificate)certificate));
		return (TrustedListsCertificateSource) adjunctCertificateSource;
	}
	
	/**
	 * Full example to validate a certificate checking revocation. Omit the 
	 * steps of loading the trusted source and intermediates if you only 
	 * want to check revocation
	 * https://stackoverflow.com/questions/42008667/how-do-i-check-if-an-x509-certificate-has-been-revoked-in-java
	 */
	public static RevocationToken validateCertificate(String trustStoreCertificate,String intermediateCertificate,String certificateToValidate){
		//Load the certification chain, including the intemediate certificates and the trusted root.    
		CertificateToken issuerCert = DSSUtils.loadCertificate(new File(trustStoreCertificate));//"/trusted.crt"
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(issuerCert);

		CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
		CertificateToken intermediateCert = DSSUtils.loadCertificate(new File(intermediateCertificate));//"/intermediate.cer"
		adjunctCertificateSource.addCertificate(intermediateCert);

		//Load the certificate to verify
		CertificateToken toValidateX509Certificate = DSSUtils.loadCertificate(certificateToValidate);//"/toValidate.crt"
		CertificateToken toValidateCertificateToken = adjunctCertificateSource.addCertificate(toValidateX509Certificate);

		//Configure the certificate verifier using the trust store and the intermediate certificates
		//OnlineOCSPSource and OnlineCRLSource will invoke the OCSP service and CRL
		//distribution point extracting the URL  from the certificate
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSource(trustedCertificateSource);
		certificateVerifier.setAdjunctCertSource(adjunctCertificateSource);     
		certificateVerifier.setCrlSource(new OnlineCRLSource());
		certificateVerifier.setOcspSource(new OnlineOCSPSource());
		
		//Perform validation 
		CertificatePool validationPool = certificateVerifier.createValidationPool();
		SignatureValidationContext validationContext = new SignatureValidationContext(validationPool);
		validationContext.addCertificateTokenForVerification(toValidateCertificateToken);
		//validationContext.setCertificateToValidate(toValidateCertificateToken);
		validationContext.validate();
		
		//Get revocation status
		Boolean isRevoked = toValidateCertificateToken.isRevoked();//isExpired();//isRevoked();
		//RevocationToken revocationToken = toValidateCertificateToken.getRevocationToken();
		RevocationToken revocationToken = toValidateCertificateToken.getRevocationTokens().iterator().next();
		return revocationToken;
	}
	
	public static Certificate getCertificate(KeyStore keyStore,String alias) throws KeyStoreException{ 
	   Certificate cert= keyStore.getCertificate(alias);
	   return cert;
   }
   
   public static Certificate getCertificate(File keyStoreFile,String keyStoreFormat,String keyStorePassword, String alias) throws GeneralSecurityException, IOException{ 
	   KeyStore keyStore = getKeystore(keyStoreFile,keyStorePassword, keyStoreFormat);
	   Certificate cert= keyStore.getCertificate(alias);
	   return cert;
   }
   
   public KeyPair getKeyPair(File keyStoreFile,String keyStoreFormat,String keyStorePassword, String alias,String passwordCertificate) throws GeneralSecurityException, IOException {
	   KeyStore keyStore = getKeystore(keyStoreFile,keyStorePassword, keyStoreFormat);
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
   
  public static KeyStore getKeystore(File keyStoreFile,String keystoreFormat, String keyStorePassword) throws GeneralSecurityException, IOException {
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
  
  public static String getAlias(Certificate certificate,File keyStoreFile, final String keyStoreType, final String keyStorePassword) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException{
	  Map<String,Certificate> map = getSigningCertificates(keyStoreFile, keyStoreType, keyStorePassword);
	  for (Entry<String,Certificate> entry : map.entrySet()) {
          if (entry.getValue().equals(certificate)) {
              return entry.getKey();
          }
      }
	  return null;
  }
	
  public static Map<String,Certificate> getSigningCertificates(final File keyStoreFile, final String keyStoreType, final String keyStorePassword) throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
		KeyStoreCertificateSource k = new KeyStoreCertificateSource(keyStoreFile, keyStoreType,keyStorePassword);
        CertificatePool certPool = k.getCertificatePool();
        logger.debug("Retrieve '" + certPool.getNumberOfCertificates() + "' certificates on " + keyStoreFile.getName() + ".");
        Map<String,Certificate> map = new HashMap<>();
        try {
            //KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            //keyStore.load(new FileInputStream(keyStoreFile), password.toCharArray());
        	KeyStore keyStore = getKeystore(keyStoreFile, keyStoreType, keyStorePassword);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                final Certificate certificate = keyStore.getCertificate(alias);
                if (certificate != null) {
                    X509Certificate x509Certificate = (X509Certificate) certificate;
                    logger.debug("Alias Certificate " + alias + " Cert " + x509Certificate.getSubjectDN());
                    List<CertificateToken> listCertToken = certPool.getCertificateTokens();//getInstance(x509Certificate, CertificateSourceType.OTHER);                
                    if(listCertToken.isEmpty()){
                    	Certificate cert = x509Certificate;
                    	if (!map.keySet().contains(alias)) {
                    		//list.add(cert);
                    		//map.put(alias,certToken.getCertificate());
                        }                         	
                    }else{
	                    for(CertificateToken certToken : listCertToken){
	                    	if (!map.keySet().contains(alias)) {
	                    		map.put(alias,certToken.getCertificate());
	                    	}
	                    }
                    }
                }
                if (keyStore.getCertificateChain(alias) != null) {
                    for (Certificate chainCert : keyStore.getCertificateChain(alias)) {
                        logger.debug("Alias CertificateChain " + alias + " Cert " + ((X509Certificate) chainCert).getSubjectDN());
                    	List<CertificateToken> listCertToken = certPool.getCertificateTokens();//getInstance(x509Certificate, CertificateSourceType.OTHER);                
                        if(listCertToken.isEmpty()){
                        	Certificate cert = (X509Certificate) chainCert;
                        	if (!map.keySet().contains(alias)) {
	                    		map.put(alias,cert);
	                    	}                      	
                        }else{
	                    	for(CertificateToken certToken : listCertToken){
	                        	//CertificateToken certToken = certPool.getInstance((X509Certificate) chainCert, CertificateSourceType.OCSP_RESPONSE);
	                            //if (!list.contains(certToken.getCertificate())) {
	                            //    list.add(certToken.getCertificate());
	                            //} 
	                    		if (!map.keySet().contains(alias)) {
		                    		map.put(alias,certToken.getCertificate());
		                    	} 
	                        } 
                        }
                    }
                }
            }
        } catch (FileNotFoundException|GeneralSecurityException e) {
			throw new IOException(e);
		}
        //Gestiamo errore certPool
        /*
        if(list.isEmpty()){
        	for(CertificateToken certToken : k.getCertificates()){
        		list.add(certToken.getCertificate());
        	}
        }
        */
        return map;
	}
  
  	public static Map<String,PrivateKey> getPrivateKeys(KeyStore keystore,String keyStorePassword) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException{
  		Map<String,PrivateKey> keys = new HashMap<String, PrivateKey>();
  	    // List the aliases
  	    Enumeration aliases = keystore.aliases();
  	    for (; aliases.hasMoreElements(); ) {
  	        String alias = (String)aliases.nextElement();

  	        // Does alias refer to a private key?
  	        boolean b = keystore.isKeyEntry(alias);

  	        // Does alias refer to a trusted certificate?
  	        //b = keystore.isCertificateEntry(alias);
  	        if(b){
  	        	keys.put(alias,(PrivateKey) keystore.getKey(alias, keyStorePassword.toCharArray()));
  	        }
  	    }
  	    return keys;
  	}
  	
  	public static PrivateKey getPrivateKey(File keyStoreFile,String keyStoreType,String keyStorePassword,String alias) throws GeneralSecurityException, IOException{
  		KeyStore keystore = getKeystore(keyStoreFile,keyStoreType,keyStorePassword);
  		return getPrivateKey(keystore, keyStorePassword, alias);
  	}
  	
  	public static PrivateKey getPrivateKey(KeyStore keystore,String keyStorePassword,String alias) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException{
  		try{
 	       //KeyStore keystore = getKeystore(passwordKeystore.toCharArray(),keystoreFormat,pathToKeystore);
 	       Certificate[] chain = keystore.getCertificateChain(alias);
 	       if(chain != null && chain.length > 0){
 	    	   return (PrivateKey) keystore.getKey(alias, keyStorePassword.toCharArray());
 	       }else{
 	    	   throw new java.lang.NullPointerException("The certificate with alias="+alias+ " is not been found");
 	       }
        }catch(java.lang.NullPointerException ex){
     	   logger.error("Make sure to have set a password for the keystore on the object SignUtils");
     	   throw new KeyStoreException("Make sure to have set a password for the keystore on the object SignUtils",ex);
        }
  	}
  	
  	public static Map<String,PublicKey> getPublicKeys(KeyStore keystore,String keyStorePassword) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException{
  		Map<String,PublicKey> keys = new HashMap<>();
  	    // List the aliases
  	    Enumeration aliases = keystore.aliases();
  	    for (; aliases.hasMoreElements(); ) {
  	        String alias = (String)aliases.nextElement();

  	        // Does alias refer to a private key?
  	        //boolean b = keystore.isKeyEntry(alias);

  	        // Does alias refer to a trusted certificate?
  	        boolean b = keystore.isCertificateEntry(alias);
  	        if(b){
  	        	keys.put(alias,(PublicKey) keystore.getKey(alias, keyStorePassword.toCharArray()));
  	        }
  	    }
  	    return keys;
  	}
	
	//==========================================================
	// METODI del DSSUtils.java di ultima versione
	//https://github.com/esig/dss/blob/master/dss-spi/src/main/java/eu/europa/esig/dss/DSSUtils.java
	//==========================================================
	
	/**
	 * This method digests the given string with SHA1 algorithm and encode returned array of bytes as hex string.
	 *
	 * @param stringToDigest
	 *            Everything in the name
	 * @return hex encoded digest value
	 */
//	public static String getSHA1Digest(final String stringToDigest) {
//		final byte[] digest = getMessageDigest(DigestAlgorithm.SHA1).digest(stringToDigest.getBytes());
//		return DSSUtils.toHex(digest);
//	}

	/**
	 * This method allows to digest the data with the given algorithm.
	 *
	 * @param digestAlgorithm
	 *            the algorithm to use
	 * @param data
	 *            the data to digest
	 * @return digested array of bytes
	 */
	public static byte[] digest(final DigestAlgorithm digestAlgorithm, final byte[] data) throws DSSException {
		final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
		// Calculate data digest
		//messageDigest.update(data);
		//byte[] digestValue = messageDigest.digest();
		final byte[] digestValue = messageDigest.digest(data);
		return digestValue;
	}

	/**
	 * @param digestAlgorithm
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static MessageDigest getMessageDigest(final DigestAlgorithm digestAlgorithm) {
		try {
			final String digestAlgorithmOid = digestAlgorithm.getOid();
			final MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithmOid, BouncyCastleProvider.PROVIDER_NAME);
			return messageDigest;
		} catch (GeneralSecurityException e) {
			throw new DSSException("Digest algorithm '" + digestAlgorithm.getName() + "' error: " + e.getMessage(), e);
		}
	}

	/**
	 * This method allows to digest the data in the {@code InputStream} with the given algorithm.
	 *
	 * @param digestAlgo
	 *            the algorithm to use
	 * @param inputStream
	 *            the data to digest
	 * @return digested array of bytes
	 */
	public static byte[] digest(final DigestAlgorithm digestAlgo, final InputStream inputStream) throws DSSException {
		try {

			final MessageDigest messageDigest = getMessageDigest(digestAlgo);
			final byte[] buffer = new byte[4096];
			int count = 0;
			while ((count = inputStream.read(buffer)) > 0) {
				messageDigest.update(buffer, 0, count);
			}
			final byte[] digestValue = messageDigest.digest();
			return digestValue;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] digest(DigestAlgorithm digestAlgorithm, DSSDocument document) {
		try (InputStream is = document.openStream()) {
			return digest(digestAlgorithm, is);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	public static byte[] digest(DigestAlgorithm digestAlgorithm, byte[]... data) {
		final MessageDigest messageDigest = getMessageDigest(digestAlgorithm);
		for (final byte[] bytes : data) {

			messageDigest.update(bytes);
		}
		final byte[] digestValue = messageDigest.digest();
		return digestValue;
	}
	
	@Deprecated
	public static  byte[] getDigest(byte []data, String hashAlgorithm) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
		return digest.digest(data);
	}
	
	@Deprecated
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
	
	@Deprecated
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
		
	
	//==========================================================
	// METODI del Utils.java di ultima versione
	//https://github.com/esig/dss/blob/master/dss-utils/src/main/java/eu/europa/esig/dss/utils/Utils.java
	//==========================================================
	/**
	 * SignedData.certificates shall be present in B/T/LT/LTA
	 */
	public static boolean checkSignedDataCertificatesPresent(SignedData signedData) throws Exception {
		ASN1Set certificates = signedData.getCertificates();
		logger.info("CERTIFICATES (" + certificates.size() + ") : " + certificates);
		for (int i = 0; i < certificates.size(); i++) {
			ASN1Sequence seqCertif = ASN1Sequence.getInstance(certificates.getObjectAt(i));
			X509CertificateHolder certificateHolder = new X509CertificateHolder(seqCertif.getEncoded());
			CertificateToken certificate = DSSASN1Utils.getCertificate(certificateHolder);
			try{
				certificate.getCertificate().checkValidity();				
			}catch(CertificateExpiredException ce){
				logger.error("The certificate " + certificate.getCertificate().getSubjectDN() + " has expired.");
				return false;
			}catch(CertificateNotYetValidException ca){
				logger.error("The certificate " + certificate.getCertificate().getSubjectDN() + " is not yet valid.");
				return false;
			}
		}
		return true;
	}

	public String retrievePolicyId(DSSDocument document,String idSignature) {
		DocumentValidator val = new XMLDocumentValidator(document);
		val.setSignaturePolicyProvider(new SignaturePolicyProvider());
		val.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = val.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		for (SignatureWrapper sig : signatures) {
			logger.info("policy id " + sig.getPolicyId());
			return diagnosticData.getSignatureById(idSignature).getPolicyId();
		}
		return null;
	}
	
	public static Reports validateDetachedContents(DSSDocument document,DSSDocument detachedFilePath,CertificateToken certificateToken){		  
		 SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);   
		 CommonCertificateVerifier verifier = new CommonCertificateVerifier();   
		 final CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource(); 
		 ServiceInfo mockServiceInfo = new MockServiceInfo(); 
		 commonTrustedCertificateSource.addCertificate(certificateToken, mockServiceInfo); 
		 verifier.setTrustedCertSource(commonTrustedCertificateSource);   
		 validator.setCertificateVerifier(verifier);   
		 List<DSSDocument> detachedContentsList= new ArrayList<DSSDocument>(); 
		 //=================================================================================
		 //String detachedFilePath = getPathFromResource("/cookbook/xml_example.xml"); 
		 //DSSDocument detachedContents = new FileDocument(detachedFilePath); detachedContentsList.add(detachedContents); 
		 validator.setDetachedContents(detachedContentsList);   
		 //=================================================================================
		 final Reports reports = validator.validateDocument(); 
		 DiagnosticData diagnosticData = reports.getDiagnosticData(); 
		 logger.info(diagnosticData.getDocumentName()); 
		 return reports;
	}
	
	public static Reports validateDetachedContents(DSSDocument document,DSSDocument detachedFilePath,DSSPrivateKeyEntry privateKey){
		final CertificateToken[] certificateChain = privateKey.getCertificateChain();
		final CertificateToken trustedCertificate = certificateChain[0];
		// Already signed document
		//DSSDocument document = new FileDocument("target/signedPdfPadesBDetached.pdf");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		CommonCertificateVerifier verifier = new CommonCertificateVerifier();
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		ServiceInfo mockServiceInfo = new MockServiceInfo();
		commonTrustedCertificateSource.addCertificate(trustedCertificate, mockServiceInfo);
		verifier.setTrustedCertSource(commonTrustedCertificateSource);
		validator.setCertificateVerifier(verifier);
		// DOCUMENT TO SIGN
		List<DSSDocument> detachedContentsList = new ArrayList<DSSDocument>();
		//String detachedFilePath = getPathFromResource("/hello-world.pdf");
		//DSSDocument detachedContents = new FileDocument(detachedFilePath);
		//detachedContentsList.add(detachedContents);
		detachedContentsList.add(detachedFilePath);
		validator.setDetachedContents(detachedContentsList);

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		DetailedReport detailedReport = reports.getDetailedReport();
		SimpleReport simpleReport = reports.getSimpleReport();
		return reports;
	}
	 
	//===========================================================================================================================================
//	/**
//	 * In case of an enveloping signature if the signed content's content is null then the null is returned.
//	 *
//	 * @param dssDocument {@code DSSDocument} containing the data to be signed or {@code CMSSignedData}
//	 * @param parameters  set of driving signing parameters
//	 * @return the {@code CMSSignedData} if the dssDocument is an CMS signed message. Null otherwise.
//	 */
//	public static CMSSignedData getCmsSignedData(final DSSDocument dssDocument, final CAdESSignatureParameters parameters) {
//
//		CMSSignedData cmsSignedData = null;
//		try {
//			// check if input dssDocument is already signed
//			cmsSignedData = new CMSSignedData(dssDocument.openStream());
//			final SignaturePackaging signaturePackaging = parameters.getSignaturePackaging();
//			if (signaturePackaging == SignaturePackaging.ENVELOPING) {
//
//				if (cmsSignedData.getSignedContent().getContent() == null) {
//					cmsSignedData = null;
//				}
//			}
//		} catch (Exception e) {
//			// not a parallel signature
//		}
//		return cmsSignedData;
//	}
//	
//	/**
//	 * In case of an enveloping signature if the signed content's content is null then the null is returned.
//	 *
//	 * @param dssDocument
//	 *            {@code DSSDocument} containing the data to be signed or {@code CMSSignedData}
//	 * @param parameters
//	 *            set of driving signing parameters
//	 * @return the {@code CMSSignedData} if the dssDocument is an CMS signed message. Null otherwise.
//	 */
//	public static CMSSignedData getCmsSignedDatav2(final DSSDocument dssDocument, final CAdESSignatureParameters parameters) {
//		CMSSignedData cmsSignedData = null;
//		if (DSSASN1Utils.isASN1SequenceTag(DSSUtils.readFirstByte(dssDocument))) {
//			try {
//				cmsSignedData = new CMSSignedData(DSSUtils.toByteArray(dssDocument));
//				if (SignaturePackaging.ENVELOPING == parameters.getSignaturePackaging() && cmsSignedData.getSignedContent().getContent() == null) {
//					cmsSignedData = null;
//				}
//			} catch (Exception e) {
//				// not a parallel signature
//			}
//		}
//		return cmsSignedData;
//	}
	
	//https://github.com/joschi/cryptoworkshop-bouncycastle/blob/master/src/main/java/cwguide/BcUtils.java
	
	/**
     * This method will calculate the Digest of the original document and create a DigestDocument to
     *  be used for document validation
     *  https://ec.europa.eu/cefdigital/tracker/browse/DSS-1259
     * @param digestValue
     * @param digestAlgorithm
     * @param origin
     * @return
     */
    public static DSSDocument toDSSDocumentUsingDigest(final String digestValue,final DigestAlgorithm digestAlgorithm ,final String origin) {
        DigestDocument retValue = null;
        if (null != digestAlgorithm) {
            retValue = new DigestDocument();
            retValue.addDigest(digestAlgorithm,origin);
            retValue.setName("Bla BLA");
        }
        return retValue;
    }
    
	

    // https://svn.apache.org/repos/asf/cxf/tags/cxf-2.4.1/distribution/src/main/release/samples/sts_issue_operation/src/main/java/demo/sts/provider/cert/CertificateVerifier.java
//
//    /**
//     * Checks whether given X.509 certificate is self-signed.
//     */
//    public static boolean isSelfSigned(X509Certificate cert)
//            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException
//    {    
//        // Try to verify certificate signature with its own public key
//        PublicKey key = cert.getPublicKey();
//        try {
//			cert.verify(key);
//			return true; 
//		} catch (InvalidKeyException|SignatureException e) {
//			return false;
//		}
//           
//    }

	public static BigInteger generateSerialNumber() {
		Random rand = new Random();
        BigInteger upperLimit = new BigInteger("100");
        BigInteger result;
        do {
            result = new BigInteger(upperLimit.bitLength(), rand); // (2^4-1) = 15 is the maximum value
        }while(result.compareTo(upperLimit) >= 0);   // exclusive of 13
        return result;
	}
	
	/**
	 * https://stackoverflow.com/questions/46856154/using-existing-intermediate-ca-key-and-cert-with-keytool-to-generate-client-cert
	 * http://javadoc.iaik.tugraz.at/iaik_jce/old/iaik/x509/extensions/ExtendedKeyUsage.html
	 * @param currentPublicKey
	 * @param currentPrivateKey
	 * @param certificateToExtend
	 * @return
	 * @throws CertIOException 
	 * @throws OperatorCreationException 
	 * @throws NoSuchAlgorithmException 
	 * @throws CertificateException 
	 * @throws Exception
	 */
	public static X509Certificate buildEndEntityCert(PublicKey currentPublicKey, PrivateKey currentPrivateKey, X509Certificate certificateToExtend) throws CertIOException, OperatorCreationException, NoSuchAlgorithmException, CertificateException {
		int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week
		String name = "CN=Test";
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
	    /*
	    ExtendedKeyUsage extKeyUsage = new ExtendedKeyUsage();
	    //add purposes
	    extKeyUsage.addKeyPurposeID(ExtendedKeyUsage.codeSigning);
	    extKeyUsage.addKeyPurposeID(ExtendedKeyUsage.timeStamping);
	    extKeyUsage.setCritical(true);
	    cert.addExtension(keyUsage);
		*/
	    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(currentPrivateKey);

	    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBldr.build(contentSigner));
	}
	
	/**
     * This method will calculate the Digest of the original document and create a DigestDocument to be used for document validation
     * @param digestValue
     * @param digestAlgorithm
     * @param origin
     * @return
     */
    public static DigestDocument  toDSSDocumentUsingDigest(DSSDocument fileToSign,final DigestAlgorithm digestAlgorithm) {
    	//String name = new SimpleDateFormat("yyyyMMdd").format(Calendar.getInstance().getTime())+".tmp";
    	//File toTempSignDocument = File.createTempFile(name, ".tmp");
    	//FileUtils.writeByteArrayToFile(toTempSignDocument,fileToSign);
    	String base64EncodeDigest = Base64.encodeBase64String(digest(digestAlgorithm,fileToSign));
    	DigestDocument retValue = null;
        if (null != digestAlgorithm) {
            retValue = new DigestDocument();
            retValue.addDigest(digestAlgorithm,base64EncodeDigest);
            retValue.setName(fileToSign.getName());
            retValue.setMimeType(fileToSign.getMimeType());
            retValue.setAbsolutePath(fileToSign.getAbsolutePath());
            //retValue.save(filePath);
        }
        return retValue;
    }
    
    public static boolean validateCertificateTSP(X509Certificate paramX509Certificate)		    
	{
	  	try{
			    if (paramX509Certificate.getVersion() != 3)
			      throw new IllegalArgumentException("Certificate must have an ExtendedKeyUsage extension.");
			    byte[] arrayOfByte = paramX509Certificate.getExtensionValue(X509Extensions.ExtendedKeyUsage.getId());
			    if (arrayOfByte == null)
			      throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension.");
			    if (!(paramX509Certificate.getCriticalExtensionOIDs().contains(X509Extensions.ExtendedKeyUsage.getId())))
			      throw new TSPValidationException("Certificate must have an ExtendedKeyUsage extension marked as critical.");
			    ASN1InputStream localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(arrayOfByte));
			    try
			    {
			      localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString)localASN1InputStream.readObject()).getOctets()));
			      ExtendedKeyUsage localExtendedKeyUsage = ExtendedKeyUsage.getInstance(localASN1InputStream.readObject());
			      if ((!(localExtendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping))) || (localExtendedKeyUsage.size() != 1))
			        throw new TSPValidationException("ExtendedKeyUsage not solely time stamping.");
			      
			      return true;
			    }
			    catch (IOException localIOException)
			    {
			      throw new TSPValidationException("cannot process ExtendedKeyUsage extension");
			    }
	  	}catch(TSPException ex){
	  		logger.error(ex.getMessage(),ex);
	  		return false;
	  	}
	}
}
