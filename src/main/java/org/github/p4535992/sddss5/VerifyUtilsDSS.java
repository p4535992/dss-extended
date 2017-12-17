package org.github.p4535992.sddss5;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSS5Utils;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DSSXmlErrorListener;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureForm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class VerifyUtilsDSS<SP extends AbstractSignatureParameters> extends AbstractPkiFactoryTestDocumentSignatureService<SP>{
	
	private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(VerifyUtilsDSS.class);
	
	private int counter;
	private DocumentSignatureService<SP> service;
	private SP signatureParameters;
	private DSSDocument documentToSign;
	protected SignedData signedData;
	protected SignerInfo signerInfo;
	protected Reports reports;
	
	private Templates templateSimpleReport;
	private Templates templateDetailedReport;
	private AdvancedSignature signature;
	
	public void init() throws TransformerConfigurationException {
		TransformerFactory transformerFactory = DomUtils.getSecureTransformerFactory();

		InputStream simpleIS = VerifyUtilsDSS.class.getResourceAsStream("/xslt/html/simple-report.xslt");
		templateSimpleReport = transformerFactory.newTemplates(new StreamSource(simpleIS));
		Utils.closeQuietly(simpleIS);

		InputStream detailedIS = VerifyUtilsDSS.class.getResourceAsStream("/xslt/html/detailed-report.xslt");
		templateDetailedReport = transformerFactory.newTemplates(new StreamSource(detailedIS));
		Utils.closeQuietly(detailedIS);
	}

	public VerifyUtilsDSS(DSSDocument signedDocument,SignatureLevel signatureLevel,CertificateToken certificateToken,CertificateSourceType certificateSourceType) 
			throws Exception {
		init();
		/*
		ASN1InputStream asn1sInput = new ASN1InputStream(signedDocument.openStream());
		ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();
		if(2!=asn1Seq.size()){
			return;
		}
		ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Seq.getObjectAt(0));
		if(!PKCSObjectIdentifiers.signedData.equals(oid)){
			return;
		}
		ASN1TaggedObject taggedObj = DERTaggedObject.getInstance(asn1Seq.getObjectAt(1));
		signedData = SignedData.getInstance(taggedObj.getObject());

		ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
		if(1!=signerInfosAsn1.size()){
			return;
		}
		signerInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));	
		IOUtils.closeQuietly(asn1sInput);
		*/
		//DSSDocument signedDocument = getSignedDocument();
		//onDocumentSigned(IOUtils.toByteArray(signedDocument.openStream()));
		
		CertificatePool certificatePool = new CertificatePool();
		certificatePool.getInstance(certificateToken, certificateSourceType);
		
		if(signatureLevel.getSignatureForm().equals(SignatureForm.CAdES)){
			signature = new CAdESSignature(IOUtils.toByteArray(signedDocument.openStream()),certificatePool);
		}else if(signatureLevel.getSignatureForm().equals(SignatureForm.PAdES)){
			//PdfSignatureInfo pdfSignatureInfo = new PdfBoxSignatureInfo()
			//signature = new PAdESSignature(signedDocument,null,certificatePool);
		}else if(signatureLevel.getSignatureForm().equals(SignatureForm.XAdES)){
			//INPUTSTREAM TO XML DOC
		    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		    dbf.setValidating(false);
		    dbf.setIgnoringComments(false);
		    dbf.setIgnoringElementContentWhitespace(true);
		    dbf.setNamespaceAware(true);
		    // dbf.setCoalescing(true);
		    // dbf.setExpandEntityReferences(true);
	        DocumentBuilder db = dbf.newDocumentBuilder();
	        //db.setEntityResolver(new NullResolver());
	        // db.setErrorHandler( new MyErrorHandler());
			Document doc = db.parse(signedDocument.openStream());
			Element elemToSign = doc.getDocumentElement();
			signature = new XAdESSignature(elemToSign,certificatePool);
		}else if(signatureLevel.getSignatureForm().equals(SignatureForm.PKCS7)){
			//TODO verificare come fare
			//signaturem = new PKCS7
		}else{
			throw new IOException("Can't verify this specific level of signature");
		}
	}
	
	@Override
	public void onDocumentSigned(byte[] byteArray) {
		try {
			
//			if(super.cmsSignedData==null){
//				logger.warn("CMSSignedDta is NULL");
//				return;
//			}

			ASN1InputStream asn1sInput = new ASN1InputStream(byteArray);
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

			logger.info("SEQ : " + asn1Seq.toString());

			if(2!=asn1Seq.size()){
				logger.warn("ASN1Sequence must be size of 2");
				return;
			}

			ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Seq.getObjectAt(0));
			if(PKCSObjectIdentifiers.signedData!=oid){
				logger.warn("The oid : " +oid.toString() + " is not equal to the CMSIgnedData identifier");
				return;
			}			
			logger.info("OID : " + oid.toString());

			ASN1TaggedObject taggedObj = DERTaggedObject.getInstance(asn1Seq.getObjectAt(1));

			logger.info("TAGGED OBJ : " + taggedObj.toString());

			ASN1Primitive object = taggedObj.getObject();
			logger.info("OBJ : " + object.toString());

			SignedData signedData = SignedData.getInstance(object);
			logger.info("SIGNED DATA : " + signedData.toString());

			ASN1Set digestAlgorithms = signedData.getDigestAlgorithms();
			logger.info("DIGEST ALGOS : " + digestAlgorithms.toString());

			ContentInfo encapContentInfo = signedData.getEncapContentInfo();
			logger.info("ENCAPSULATED CONTENT INFO : " + encapContentInfo.getContentType() + " " + encapContentInfo.getContent());

			ASN1Set certificates = signedData.getCertificates();
			logger.info("CERTIFICATES (" + certificates.size() + ") : " + certificates);

			List<X509Certificate> foundCertificates = new ArrayList<X509Certificate>();
			for (int i = 0; i < certificates.size(); i++) {
				ASN1Sequence seqCertif = ASN1Sequence.getInstance(certificates.getObjectAt(i));
				logger.info("SEQ cert " + i + " : " + seqCertif);

				X509CertificateHolder certificateHolder = new X509CertificateHolder(seqCertif.getEncoded());
				CertificateToken certificate = DSSASN1Utils.getCertificate(certificateHolder);
				X509Certificate x509Certificate = certificate.getCertificate();
				x509Certificate.checkValidity();

				logger.info("Cert " + i + " : " + certificate);

				foundCertificates.add(x509Certificate);
			}

			ASN1Set crLs = signedData.getCRLs();
			logger.info("CRLs : " + crLs);

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			logger.info("SIGNER INFO ASN1 : " + signerInfosAsn1.toString());
			if(1!=signerInfosAsn1.size()){
				logger.warn("ASN1Set of info must be size of 1");
				return;
			}

			ASN1Sequence seqSignedInfo = ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0));

			SignerInfo signedInfo = SignerInfo.getInstance(seqSignedInfo);
			logger.info("SIGNER INFO : " + signedInfo.toString());

			SignerIdentifier sid = signedInfo.getSID();
			logger.info("SIGNER IDENTIFIER : " + sid.getId());

			IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(signedInfo.getSID());
			logger.info("ISSUER AND SN : " + issuerAndSerialNumber.toString());

			BigInteger serial = issuerAndSerialNumber.getSerialNumber().getValue();

			X509Certificate signerCertificate = null;
			for (X509Certificate x509Certificate : foundCertificates) {
				// TODO check issuer name
				if (serial.equals(x509Certificate.getSerialNumber())) {
					signerCertificate = x509Certificate;
				}
			}
			if(signerCertificate==null){
				logger.warn("The signerCertificate is NULL");
				return;
			}

			ASN1OctetString encryptedDigest = signedInfo.getEncryptedDigest();
			logger.info("ENCRYPT DIGEST : " + encryptedDigest.toString());

			ASN1Sequence seq = ASN1Sequence.getInstance(object);

			ASN1Integer version = ASN1Integer.getInstance(seq.getObjectAt(0));
			logger.info("VERSION : " + version.toString());

			ASN1Set digestManualSet = ASN1Set.getInstance(seq.getObjectAt(1));
			logger.info("DIGEST SET : " + digestManualSet.toString());
			if(digestAlgorithms!=digestManualSet){
				logger.warn("digestAlgorithms!=digestManualSet");
				return;
			}

			ASN1Sequence seqDigest = ASN1Sequence.getInstance(digestManualSet.getObjectAt(0));
			// assertEquals(1, seqDigest.size());

			ASN1ObjectIdentifier oidDigestAlgo = ASN1ObjectIdentifier.getInstance(seqDigest.getObjectAt(0));
			if((new ASN1ObjectIdentifier(DigestAlgorithm.SHA256.getOid()))!=oidDigestAlgo){
				logger.warn("new ASN1ObjectIdentifier(DigestAlgorithm.SHA256.getOid()))!=oidDigestAlgo");
				return;
			}

			ASN1Sequence seqEncapsulatedInfo = ASN1Sequence.getInstance(seq.getObjectAt(2));
			logger.info("ENCAPSULATED INFO : " + seqEncapsulatedInfo.toString());

			ASN1ObjectIdentifier oidContentType = ASN1ObjectIdentifier.getInstance(seqEncapsulatedInfo.getObjectAt(0));
			logger.info("OID CONTENT TYPE : " + oidContentType.toString());

			ASN1TaggedObject taggedContent = DERTaggedObject.getInstance(seqEncapsulatedInfo.getObjectAt(1));

			ASN1OctetString contentOctetString = ASN1OctetString.getInstance(taggedContent.getObject());
			String content = new String(contentOctetString.getOctets());
			//assertEquals(HELLO_WORLD, content);
			logger.info("CONTENT : " + content);

			byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, content.getBytes());
			String encodeHexDigest = Hex.toHexString(digest);
			logger.info("CONTENT DIGEST COMPUTED : " + encodeHexDigest);

			ASN1Set authenticatedAttributes = signedInfo.getAuthenticatedAttributes();
			logger.info("AUTHENTICATED ATTRIBUTES : " + authenticatedAttributes.toString());

			// ASN1Sequence seqAuthAttrib = ASN1Sequence.getInstance(authenticatedAttributes.getObjectAt(0));

			logger.info("Nb Auth Attributes : " + authenticatedAttributes.size());

			String embeddedDigest = "";
			for (int i = 0; i < authenticatedAttributes.size(); i++) {
				ASN1Sequence authAttrSeq = ASN1Sequence.getInstance(authenticatedAttributes.getObjectAt(i));
				logger.info(authAttrSeq.toString());
				ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(authAttrSeq.getObjectAt(0));
				if (PKCSObjectIdentifiers.pkcs_9_at_messageDigest.equals(attrOid)) {
					ASN1Set setMessageDigest = ASN1Set.getInstance(authAttrSeq.getObjectAt(1));
					ASN1OctetString asn1ObjString = ASN1OctetString.getInstance(setMessageDigest.getObjectAt(0));
					embeddedDigest = Hex.toHexString(asn1ObjString.getOctets());
				}
			}
			if(encodeHexDigest!=embeddedDigest){
				logger.warn("encodeHexDigest!=embeddedDigest");
				return;
			}

			ASN1OctetString encryptedInfoOctedString = signedInfo.getEncryptedDigest();
			String signatureValue = Hex.toHexString(encryptedInfoOctedString.getOctets());

			logger.info("SIGNATURE VALUE : " + signatureValue);

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, signerCertificate);
			byte[] decrypted = cipher.doFinal(encryptedInfoOctedString.getOctets());

			ASN1InputStream inputDecrypted = new ASN1InputStream(decrypted);

			ASN1Sequence seqDecrypt = (ASN1Sequence) inputDecrypted.readObject();
			logger.info("Decrypted : " + seqDecrypt);

			DigestInfo digestInfo = new DigestInfo(seqDecrypt);
			if(oidDigestAlgo!=digestInfo.getAlgorithmId().getAlgorithm()){
				logger.warn("oidDigestAlgo!=digestInfo.getAlgorithmId().getAlgorithm()");
				return;
			}

			String decryptedDigestEncodeBase64 = Utils.toBase64(digestInfo.getDigest());
			logger.info("Decrypted Base64 : " + decryptedDigestEncodeBase64);

			byte[] encoded = signedInfo.getAuthenticatedAttributes().getEncoded();
			MessageDigest messageDigest = MessageDigest.getInstance(DigestAlgorithm.SHA256.getName());
			byte[] digestOfAuthenticatedAttributes = messageDigest.digest(encoded);

			String computedDigestEncodeBase64 = Utils.toBase64(digestOfAuthenticatedAttributes);
			logger.info("Computed Base64 : " + computedDigestEncodeBase64);

			if(decryptedDigestEncodeBase64!=computedDigestEncodeBase64){
				logger.warn("decryptedDigestEncodeBase64!=computedDigestEncodeBase64");
				return;
			}

			Utils.closeQuietly(asn1sInput);
			Utils.closeQuietly(inputDecrypted);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);			
		}
	}
	
	@Override
	protected DocumentSignatureService<SP> getService() {
		return service;
	}

	@Override
	protected SP getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.PKCS7;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
	
	//=========================================================================================
	
	/*
	public boolean checkContentTypePresent() {
		return isSignedAttributeFound(PKCSObjectIdentifiers.pkcs_9_at_contentType);
	}

	public boolean checkMessageDigestPresent() {
		return isSignedAttributeFound(PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
	}

	public boolean checkSigningTimePresent() {
		return isSignedAttributeFound(PKCSObjectIdentifiers.pkcs_9_at_signingTime);
	}

//	public boolean checkSignatureTimeStampPresent() {
//		return isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
//	}
    
	public boolean checkSignatureTimeStampPresent() {
		// Not present in baseline B
    	return false;
	}
	
	public boolean checkCertificateValue() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certValues);
		return ((counter == 0) || (counter == 1));
	}

	
	public boolean checkCompleteCertificateReference() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
		return ((counter == 0) || (counter == 1));
	}

	
	public boolean checkRevocationValues() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
		return ((counter == 0) || (counter == 1));
	}

	
	public boolean checkCompleteRevocationReferences() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);
		return ((counter == 0) || (counter == 1));
	}

	
	public boolean checkTimestamp() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp);
		return (counter >= 0);
	}

	
	public boolean checkTimestampedCertsCrlsReferences() {
		int counter = countUnsignedAttribute(PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp);
		return (counter >= 0);
	}

	//=======================================================================================================================
	
	protected boolean isSignedAttributeFound(ASN1ObjectIdentifier oid) {
		return countSignedAttribute(oid) > 0;
	}

	protected boolean isUnsignedAttributeFound(ASN1ObjectIdentifier oid) {
		return countUnsignedAttribute(oid) > 0;
	}

	protected int countSignedAttribute(ASN1ObjectIdentifier oid) {
		ASN1Set authenticatedAttributes = signerInfo.getAuthenticatedAttributes();
		return countInSet(oid, authenticatedAttributes);
	}

	protected int countUnsignedAttribute(ASN1ObjectIdentifier oid) {
		ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
		return countInSet(oid, unauthenticatedAttributes);
	}

	private int countInSet(ASN1ObjectIdentifier oid, ASN1Set set) {
		int counter = 0;
		if (set != null) {
			for (int i = 0; i < set.size(); i++) {
				ASN1Sequence attrSeq = ASN1Sequence.getInstance(set.getObjectAt(i));
				ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(attrSeq.getObjectAt(0));
				if (oid.equals(attrOid)) {
					counter++;
				}
			}
		}
		return counter;
	}
	*/
	

	
	//=======================================================================================================================
	
	
	 public static void main(String[] args) throws Exception{
			
			//SET PROXY
		  	System.setProperty("http.proxySet", "true");
	        System.setProperty("http.proxyHost", "192.168.1.188");
	        System.setProperty("http.proxyPort", "3128");
	        System.setProperty("https.proxyHost", "192.168.1.188");
	        System.setProperty("https.proxyPort", "3128");
	        ClassLoader classLoader = Thread.currentThread().getContextClassLoader(); 
			
	    	File fileToSign = new File("C:\\Users\\pancio\\Desktop\\test_firma\\new 3.txt");
			File targetFile = new File("C:\\Users\\pancio\\Desktop\\test_firma\\new 3.txt.p7m");
			File keyStoreFile = new File("C:\\Users\\pancio\\Desktop\\test_firma\\testKeystore3.jks");
	        //File fileToSign = new File(SignUtilsSDDSS5.class.getResource("/test_firma/new 3.txt").toURI());
	        //File targetFile = new File(SignUtilsSDDSS5.class.getResource("/test_firma/new 3.txt.p7m").toURI());
	        //File keyStoreFile = new File(SignUtilsSDDSS5.class.getResource("/test_firma/testKeystore.jks").toURI());
			String keyStorePassword = "changeit";
			String keyStoreType = "JKS";
			Map<String,Certificate> map = DSS5Utils.getSigningCertificates(keyStoreFile, "JKS", keyStorePassword);
			Certificate certificate = DSS5Utils.getCertificate(keyStoreFile, keyStorePassword, "JKS", "testFirma");
			CertificateToken certificateToken = new CertificateToken((X509Certificate) certificate);
			DSSDocument signedDocument = new FileDocument(targetFile);
			DSSDocument originalDocument = new FileDocument(fileToSign);
			
			VerifyUtilsDSS<CAdESSignatureParameters> v = new VerifyUtilsDSS<CAdESSignatureParameters>(
					signedDocument,SignatureLevel.CAdES_BASELINE_B,certificateToken,CertificateSourceType.SIGNATURE);
			v.onDocumentSigned(IOUtils.toByteArray(signedDocument.openStream()));
			
			v.checkReports(signedDocument, ValidationLevel.BASIC_SIGNATURES);
			//=======================================================================================
	}  
	 
	 public DSSDocument tryToGetOriginalDocument(DSSDocument signedDocument) throws CMSException, DSSException, IOException{
		 //byte[] signedData = Base64.decodeBase64(IOUtils.toByteArray(signedDocument.openStream()));
		 byte[] signedData = IOUtils.toByteArray(signedDocument.openStream());
		 CMSSignedData csd = new CMSSignedData(signedData);
		 CMSProcessableByteArray cpb = (CMSProcessableByteArray)csd.getSignedContent();
		 byte[] originalContent = (byte[]) cpb.getContent();
		 return new InMemoryDocument(originalContent);
	 }
	 	 
	 public Reports checkReports(DSSDocument signedDocument,ValidationLevel validationLevel) throws DSSException, CMSException, IOException{
		    File policyFile = null;
			
			//ValidationLevel validationLevel = ValidationLevel.BASIC_SIGNATURES;
			
			SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
			
			TrustedListsCertificateSource certificateSource = new TrustedListsCertificateSource();
		
			CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
			OnlineCRLSource crlSource = new OnlineCRLSource();
			crlSource.setDataLoader(commonsDataLoader);
			
			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			verifier.setCrlSource(crlSource);
			
			FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
			File cacheFolder = new File(System.getProperty("java.io.tmpdir"));
			fileCacheDataLoader.setFileCacheDirectory(cacheFolder);
			
			verifier.setTrustedCertSource(certificateSource);
			verifier.setDataLoader(fileCacheDataLoader);

			validator.setCertificateVerifier(verifier);
			validator.setValidationLevel(validationLevel);
			
			//  certificateVerifier.setCrlSource(offlineCRLSource);
		    //    certificateVerifier.setOcspSource(onlineOCSPSource);
		    //    validator.setCertificateVerifier(certificateVerifier);
			/*
			Reports reports = validator.validateDocument();
			SimpleReport simpleReport = reports.getSimpleReport();
			DetailedReport detailedReport = reports.getDetailedReport();
			*/

			logger.info("Validating document :" + signedDocument.getName());
	        Reports retValue = null;
	        logger.info("Configuring validator");
	        //final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
	        DSSDocument originalDocument = tryToGetOriginalDocument(signedDocument);
	        if(null != originalDocument){
	            final List<DSSDocument> detachedContents = new ArrayList<>();
	            detachedContents.add(originalDocument);
	            logger.info("Original Document attached to the validator");
	            validator.setDetachedContents(detachedContents);
	            logger.info("Original Document attached to the validator[" + originalDocument.getName() + "]");
	        }
	        
	        logger.info("Validation level defined [" + validationLevel + "]");
	      	      	       
	        /*
	        if (!validationForm.isDefaultPolicy() && (policyFile != null) && !policyFile.isEmpty()) {
	        	InputStream dpis = null;
		        logger.info("Setting validation policy");
	        	try {
	        		dpis = policy.getInputStream();
	                logger.info("Starting document validation");
	                retValue = validator.validateDocument(dpis);
					//reports = validator.validateDocument(policyFile.getInputStream());
				 } catch (IOException e) {
	                logger.error(e.getMessage(), e);
	                throw new DSSException(e.getMessage(), e.getCause());
	            }catch(Exception e){
	                logger.error(e.getMessage(), e);
	                throw new DSSException(e.getMessage(), e.getCause());
	            }	            
			} else if (defaultPolicy != null) {
				InputStream dpis = null;
				try {
					dpis = defaultPolicy.getInputStream();
					reports = documentValidator.validateDocument(dpis);
				 } catch (IOException e) {
	                logger.error(e.getMessage(), e);
	                throw new DSSException(e.getMessage(), e.getCause());
	            }catch(Exception e){
	                logger.error(e.getMessage(), e);
	                throw new DSSException(e.getMessage(), e.getCause());
	            }
	            finally {
	                Utils.closeQuietly(dpis);
	            }
			} else {
				logger.error("Not correctly initialized");
			}
	        */
	        
	        Reports reports = validator.validateDocument();
	        reports.print();
	        
			SimpleReport simpleReport = reports.getSimpleReport();
			DetailedReport detailedReport = reports.getDetailedReport();
			eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData diagnosticData = reports.getDiagnosticData();
			
			String xmlSimpleReport = reports.getXmlSimpleReport();
			String xmlDetailReport = reports.getXmlDetailedReport();	
			
			return reports;
	 }
	 
	 public String generateSimpleReport(String simpleReport) {
		Writer writer = new StringWriter();
		try {
			Transformer transformer = templateSimpleReport.newTransformer();
			transformer.setErrorListener(new DSSXmlErrorListener());
			transformer.transform(new StreamSource(new StringReader(simpleReport)), new StreamResult(writer));
		} catch (Exception e) {
			logger.error("Error while generating simple report : " + e.getMessage(), e);
		}
		return writer.toString();
	}

	public String generateSimpleReport(Document dom) {
		Writer writer = new StringWriter();
		try {
			Transformer transformer = templateSimpleReport.newTransformer();
			transformer.setErrorListener(new DSSXmlErrorListener());
			transformer.transform(new DOMSource(dom), new StreamResult(writer));
		} catch (Exception e) {
			logger.error("Error while generating simple report : " + e.getMessage(), e);
		}
		return writer.toString();
	}

	public String generateDetailedReport(String detailedReport) {
		Writer writer = new StringWriter();
		try {
			Transformer transformer = templateDetailedReport.newTransformer();
			transformer.setErrorListener(new DSSXmlErrorListener());
			transformer.transform(new StreamSource(new StringReader(detailedReport)), new StreamResult(writer));
		} catch (Exception e) {
			logger.error("Error while generating detailed report : " + e.getMessage(), e);
		}
		return writer.toString();
	}
	
	
	//=============================================================
	
}
