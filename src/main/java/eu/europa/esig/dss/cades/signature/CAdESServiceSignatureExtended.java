package eu.europa.esig.dss.cades.signature;

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

public class CAdESServiceSignatureExtended extends CAdESService{
	
	private static final Logger LOG = LoggerFactory.getLogger(CAdESServiceSignatureExtended.class);
	
	private final CMSSignedDataBuilder cmsSignedDataBuilder;

	/**
	 * id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }
	 */
    public final ASN1ObjectIdentifier id_countersignature = new ASN1ObjectIdentifier("1.2.840.113549.1.9.6");

	/**
	 * This is the constructor to create an instance of the {@code CAdESService}. A certificate verifier must be
	 * provided.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
	 */
	public CAdESServiceSignatureExtended(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);		
		cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		LOG.debug("+ CAdESService Extended created");
	}

	//https://github.com/arhs/sd-dss/blob/master/apps/dss/core/dss-document/src/main/java/eu/europa/ec/markt/dss/signature/cades/CAdESService.java
		
	/*
	public DSSDocument counterSignDocument(
			final DSSDocument toCounterSignDocument, final CAdESSignatureParameters parameters,SignatureValue signatureValue, SignerId selector) 
					throws DSSException {

		//final SignatureTokenConnection token = parameters.getSigningToken();
		if (signatureValue == null) {
			throw new DSSException("The connection through available API to the SSCD must be set.");
		}

		try {
			assertSigningDateInCertificateValidityRange(parameters);
			final SignaturePackaging packaging = parameters.getSignaturePackaging();
			//assertSignaturePackaging(packaging);

			final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
			final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());
			//final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, true);	
			
			//final InputStream inputStream = toCounterSignDocument.openStream();
			//final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
			//IOUtils.closeQuietly(inputStream);
			
			//Retrieve the original signature
			final CMSSignedData originalCmsSignedData = getCmsSignedDataFromSignedContent(toCounterSignDocument,parameters);
			if ((originalCmsSignedData == null) && SignaturePackaging.DETACHED.equals(packaging) && Utils.isCollectionEmpty(parameters.getDetachedContents())) {
				parameters.setDetachedContents(Arrays.asList(toCounterSignDocument));
			}
			
			SignerInformationStore signerInfos = originalCmsSignedData.getSignerInfos();
			SignerInformation signerInformation = signerInfos.get(selector);

			//Generate a signed digest on the contents octets of the signature octet String in the identified SignerInfo value
			//of the original signature's SignedData
			//byte[] dataToSign = signerInformation.getSignature();
			//ToBeSigned dataToSign = getDataToSign(toCounterSignDocument,parameters);					
			//SignatureValue signatureValueXX = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);//parameters.getPrivateKeyEntry()
			//byte[]  signatureValue =  signatureValueXX.getValue();
			//Set the countersignature builder
			CounterSignatureBuilder builder = new CounterSignatureBuilder(certificateVerifier);
			builder.setCmsSignedData(originalCmsSignedData);
			builder.setSelector(selector);

			//final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
			//final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());

			SignerInfoGeneratorBuilder signerInformationGeneratorBuilder = getSignerInfoGeneratorBuilder(parameters, true);
			CMSSignedDataGenerator cmsSignedDataGenerator = createCMSSignedDataGenerator(parameters, customContentSigner, signerInformationGeneratorBuilder, null);
			CMSTypedData content = originalCmsSignedData.getSignedContent();
			CMSSignedData signedData = cmsSignedDataGenerator.generate(content);
			final CMSSignedData countersignedCMSData = builder.signDocument(signedData);
			final CMSSignedDocument signature = new CMSSignedDocument(countersignedCMSData);
			return signature;

		} catch (CMSException e) {
			throw new DSSException("Cannot parse CMS data", e);
		}
	}
	*/

	/*
	public DSSDocument counterSignDocument(
			final DSSDocument toCounterSignDocument, final CAdESSignatureParameters parameters,SignatureValue signatureValue, DSSPrivateKeyEntry selector) 
					throws DSSException {

		SignerId signerId = new JcaSignerId(selector.getCertificate().getCertificate());					
		return counterSignDocument(toCounterSignDocument, parameters, signatureValue, signerId);
	}
	*/
	
	/**
	 * This method countersigns a signature identified through its SignerId
	 *
	 * @param toCounterSignDocument the original signature document containing the signature to countersign
	 * @param parameters            the signature parameters
	 * @param selector              the DSSPrivateKeyEntry identifying the signature to countersign
	 * @param signatureValue        the SignatureValue value for the current connection token
	 * @return the updated signature document, in which the countersignature has been embedded
	 * @throws IOException 
	 * @throws DSSException 
	 * @throws CertificateException 
	 * @throws OperatorCreationException 
	 */
	public DSSDocument counterSignDocument(
			final DSSDocument toCounterSignDocument, final CAdESSignatureParameters parameters,SignatureValue signatureValue, DSSPrivateKeyEntry selector) 
					throws DSSException {

		SignerId signerId = new JcaSignerId(selector.getCertificate().getCertificate());					
		return counterSignDocument(toCounterSignDocument, parameters, signatureValue, signerId);
	}
	
	
	/**
	 * This method countersigns a signature identified through its SignerId
	 *
	 * @param toCounterSignDocument the original signature document containing the signature to countersign
	 * @param parameters            the signature parameters
	 * @param selector              the SignerId identifying the signature to countersign
	 * @param signatureValue        the signatre value for the current connection token
	 * @return the updated signature document, in which the countersignature has been embedded
	 * @throws IOException 
	 * @throws DSSException 
	 * @throws CertificateException 
	 * @throws OperatorCreationException 
	 */
	public DSSDocument counterSignDocument(
			final DSSDocument toCounterSignDocument, final CAdESSignatureParameters parameters,SignatureValue signatureValue, SignerId selector) 
					throws DSSException {
		//final SignatureTokenConnection token = parameters.getSigningToken();
		if (signatureValue == null) {
			throw new DSSException("The connection through available API to the SSCD must be set.");
		}

		try {
			assertSigningDateInCertificateValidityRange(parameters);
			final SignaturePackaging packaging = parameters.getSignaturePackaging();
			//assertSignaturePackaging(packaging);

			final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
			final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());

			//Retrieve the original signature
			final CMSSignedData originalCmsSignedData = getCmsSignedDataFromSignedContent(toCounterSignDocument,parameters);
			if ((originalCmsSignedData == null) && SignaturePackaging.DETACHED.equals(packaging) && Utils.isCollectionEmpty(parameters.getDetachedContents())) {
				parameters.setDetachedContents(Arrays.asList(toCounterSignDocument));
			}
			
			//SignerInformationStore signerInfos = originalCmsSignedData.getSignerInfos();
			//SignerInformation signerInformation = signerInfos.get(selector);

			//Set the countersignature builder
		    //CounterSignatureBuilder builder = new CounterSignatureBuilder(certificateVerifier);
			//builder.setCmsSignedData(originalCmsSignedData);
			//builder.setSelector(selector);

			SignerInfoGeneratorBuilder signerInformationGeneratorBuilder = getSignerInfoGeneratorBuilder(parameters, true);
			CMSSignedDataGenerator cmsSignedDataGenerator = createCMSSignedDataGenerator(parameters, customContentSigner, signerInformationGeneratorBuilder, null);
			CMSTypedData content = originalCmsSignedData.getSignedContent();
			CMSSignedData signedData = cmsSignedDataGenerator.generate(content);
			//final CMSSignedData countersignedCMSData = builder.signDocument(signedData);
			
			final ASN1ObjectIdentifier csIdentifier = id_countersignature;//OID.id_countersignature;

			//Retrieve the SignerInformation from the countersigned signature
			final SignerInformationStore originalSignerInfos = originalCmsSignedData.getSignerInfos();
			//Retrieve the SignerInformation from the countersignature
			final SignerInformationStore signerInfos = signedData.getSignerInfos();

			//Add the countersignature
			SignerInformation originalSI = originalCmsSignedData.getSignerInfos().get(selector);
			if(originalSI==null && originalCmsSignedData.getSignerInfos().size()>0){
				originalSI = originalCmsSignedData.getSignerInfos().getSigners().iterator().next();
			}
			SignerInformation updatedSI = originalSI.addCounterSigners(originalSignerInfos.get(selector), signerInfos);

			//Create updated SignerInformationStore
			Collection<SignerInformation> counterSignatureInformationCollection = new ArrayList<SignerInformation>();
			counterSignatureInformationCollection.add(updatedSI);
			SignerInformationStore signerInformationStore = new SignerInformationStore(counterSignatureInformationCollection);

			//Return new, updated signature
			final CMSSignedData countersignedCMSData = CMSSignedData.replaceSigners(originalCmsSignedData, signerInformationStore);
			
			
			final CMSSignedDocument signature = new CMSSignedDocument(countersignedCMSData);
			return signature;

		} catch (CMSException e) {
			throw new DSSException("Cannot parse CMS data", e);
		}
		
	}
	
	
		
    /**
	 * Note:
	 * Section 5.1 of RFC 3852 [4] requires that, the CMS SignedData version be set to 3 if certificates from
	 * SignedData is present AND (any version 1 attribute certificates are present OR any SignerInfo structures
	 * are version 3 OR eContentType from encapContentInfo is other than id-data). Otherwise, the CMS
	 * SignedData version is required to be set to 1.
	 * ---> CMS SignedData Version is handled automatically by BouncyCastle.
	 *
	 * @param parameters                 set of the driving signing parameters
	 * @param contentSigner              the contentSigned to get the hash of the data to be signed
	 * @param signerInfoGeneratorBuilder true if the unsigned attributes must be included
	 * @param originalSignedData         the original signed data if extending an existing signature. null otherwise.
	 * @return the bouncycastle signed data generator which signs the document and adds the required signed and unsigned CMS attributes
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
     * @throws IOException 
     * @throws CertificateEncodingException 
	 */
	protected  CMSSignedDataGenerator createCMSSignedDataGenerator(final CAdESSignatureParameters parameters, final ContentSigner contentSigner,
	                                                              final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder,
	                                                              final CMSSignedData originalSignedData) throws DSSException{
		try {

			final X509Certificate signingCertificate = parameters.getSigningCertificate().getCertificate();

			final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			final X509CertificateHolder certHolder = new X509CertificateHolder(signingCertificate.getEncoded());
			final SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, certHolder);

			generator.addSignerInfoGenerator(signerInfoGenerator);

			final Set<X509Certificate> newCertificateChain = new HashSet<X509Certificate>();

			if (originalSignedData != null) {

				generator.addSigners(originalSignedData.getSignerInfos());
				generator.addAttributeCertificates(originalSignedData.getAttributeCertificates());
				generator.addCRLs(originalSignedData.getCRLs());
				generator.addOtherRevocationInfo(id_pkix_ocsp_basic, originalSignedData.getOtherRevocationInfo(id_pkix_ocsp_basic));
				generator.addOtherRevocationInfo(id_ri_ocsp_response, originalSignedData.getOtherRevocationInfo(id_ri_ocsp_response));

				final Store certificates = originalSignedData.getCertificates();
				final Collection<X509CertificateHolder> certificatesMatches = certificates.getMatches(null);
				for (final X509CertificateHolder certificatesMatch : certificatesMatches) {

					final X509Certificate x509Certificate = getCertificate(certificatesMatch);
					newCertificateChain.add(x509Certificate);
				}
			}
			final List<CertificateToken> certificateChain = parameters.getCertificateChain();
			for (final CertificateToken chainCertificate : certificateChain) {

				final X509Certificate x509Certificate = chainCertificate.getCertificate();
				newCertificateChain.add(x509Certificate);
			}
			final boolean trustAnchorBPPolicy = parameters.bLevel().isTrustAnchorBPPolicy();
			final Store jcaCertStore = getJcaCertStore(newCertificateChain, trustAnchorBPPolicy);
			generator.addCertificates(jcaCertStore);
			return generator;
		} catch (CMSException e) {
			throw new DSSException(e);
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * @param parameters                the parameters of the signature containing values for the attributes
	 * @param includeUnsignedAttributes true if the unsigned attributes must be included
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the CAdESLevelBaselineB
	 */
	 SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(final CAdESSignatureParameters parameters, final boolean includeUnsignedAttributes) {

		final CAdESLevelBaselineB cadesProfile = new CAdESLevelBaselineB();
		final AttributeTable signedAttributes = cadesProfile.getSignedAttributes(parameters);

		AttributeTable unsignedAttributes = null;
		if (includeUnsignedAttributes) {
			unsignedAttributes = cadesProfile.getUnsignedAttributes();
		}
		return getSignerInfoGeneratorBuilder(signedAttributes, unsignedAttributes);
	}

	/**
	 * @param signedAttributes   the signedAttributes
	 * @param unsignedAttributes the unsignedAttributes
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the parameters
	 */
	private  SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(AttributeTable signedAttributes, AttributeTable unsignedAttributes) {

		if (signedAttributes != null && signedAttributes.size() == 0) {
			signedAttributes = null;
		}
		final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributes);
		if (unsignedAttributes != null && unsignedAttributes.size() == 0) {
			unsignedAttributes = null;
		}
		final SimpleAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(unsignedAttributes);

		return getSignerInfoGeneratorBuilder(signedAttributeGenerator, unsignedAttributeGenerator);
	}

	/**
	 * @param signedAttributeGenerator   the signedAttribute generator
	 * @param unsignedAttributeGenerator the unsignedAttribute generator
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the parameters
	 */
	private  SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(DefaultSignedAttributeTableGenerator signedAttributeGenerator,
	                                                                 SimpleAttributeTableGenerator unsignedAttributeGenerator) {

		final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
		SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
		sigInfoGeneratorBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
		sigInfoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedAttributeGenerator);
		return sigInfoGeneratorBuilder;
	}

	/**
	 * The order of the certificates is important, the fist one must be the signing certificate.
	 *
	 * @return a store with the certificate chain of the signing certificate. The {@code Collection} is unique.
	 * @throws CertificateEncodingException
	 */
	private  JcaCertStore getJcaCertStore(final Collection<X509Certificate> certificateChain, boolean trustAnchorBPPolicy) {

		try {

			final Collection<X509Certificate> certs = new ArrayList<X509Certificate>();
			for (final X509Certificate certificateInChain : certificateChain) {

				// CAdES-Baseline-B: do not include certificates found in the trusted list
				if (trustAnchorBPPolicy) {

					final X500Principal subjectX500Principal = certificateInChain.getSubjectX500Principal();
					final CertificateSource trustedCertSource = certificateVerifier.getTrustedCertSource();
					if (trustedCertSource != null) {
						if (!trustedCertSource.get(subjectX500Principal).isEmpty()) {
							continue;
						}
					}
				}
				certs.add(certificateInChain);
			}
			return new JcaCertStore(certs);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	protected  CMSSignedData regenerateCMSSignedData(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters, Store certificatesStore, Store attributeCertificatesStore,
	                                                Store crlsStore, Store otherRevocationInfoFormatStoreBasic, Store otherRevocationInfoFormatStoreOcsp) {
		try {

			final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
			cmsSignedDataGenerator.addSigners(cmsSignedData.getSignerInfos());
			cmsSignedDataGenerator.addAttributeCertificates(attributeCertificatesStore);
			cmsSignedDataGenerator.addCertificates(certificatesStore);
			cmsSignedDataGenerator.addCRLs(crlsStore);
			cmsSignedDataGenerator.addOtherRevocationInfo(id_pkix_ocsp_basic, otherRevocationInfoFormatStoreBasic);
			cmsSignedDataGenerator.addOtherRevocationInfo(id_ri_ocsp_response, otherRevocationInfoFormatStoreOcsp);
			final boolean encapsulate = cmsSignedData.getSignedContent() != null;
			if (!encapsulate) {
				final InputStream inputStream = parameters.getDetachedContents().get(0).openStream();
				final CMSProcessableByteArray content = new CMSProcessableByteArray(DSSUtils.toByteArray(inputStream));
				cmsSignedData = cmsSignedDataGenerator.generate(content, encapsulate);
			} else {
				cmsSignedData = cmsSignedDataGenerator.generate(cmsSignedData.getSignedContent(), encapsulate);
			}
			return cmsSignedData;
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}
	
	private  X509Certificate getCertificate(final X509CertificateHolder x509CertificateHolder) {

		try {

			final org.bouncycastle.asn1.x509.Certificate certificate = x509CertificateHolder.toASN1Structure();
			final X509CertificateObject x509CertificateObject = new X509CertificateObject(certificate);
			return x509CertificateObject;
		} catch (CertificateParsingException e) {
			throw new DSSException(e);
		}
	}
	
	/**
	 * In case of an enveloping signature if the signed content's content is null then the null is returned.
	 *
	 * @param dssDocument
	 *            {@code DSSDocument} containing the data to be signed or {@code CMSSignedData}
	 * @param parameters
	 *            set of driving signing parameters
	 * @return the {@code CMSSignedData} if the dssDocument is an CMS signed message. Null otherwise.
	 * @throws IOException 
	 * @throws DSSException 
	 * @throws CMSException 
	 * @throws OperatorCreationException 
	 * @throws CertificateException 
	 */
	private CMSSignedData getCmsSignedDataFromSignedContent(
			DSSDocument signedDocument, final CAdESSignatureParameters parameters) 
			throws DSSException{
		Security.addProvider(new BouncyCastleProvider());  
		
		CMSSignedData cmsSignedData = null;
		if (DSSASN1Utils.isASN1SequenceTag(DSSUtils.readFirstByte(signedDocument))) {
			try {
				cmsSignedData = new CMSSignedData(DSSUtils.toByteArray(signedDocument));
				if (SignaturePackaging.ENVELOPING == parameters.getSignaturePackaging() && cmsSignedData.getSignedContent().getContent() == null) {
					cmsSignedData = null;
				}
			} catch (Exception e) {
				// not a parallel signature
			}
		}else{		
			/*
			 //PrivateKey key = dssPrivateKeyEntry;
			 List<CertificateToken> chain = parameters.getCertificateChain();
			 CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			 byte[] sig = IOUtils.toByteArray(signedDocument.openStream());  
			 //byte[] Data_Bytes = IOUtils.toByteArray(originalDocument.openStream());  
		     
			 //ASN1InputStream asn1 = new ASN1InputStream(sig);
	         //ByteArrayOutputStream out = new ByteArrayOutputStream(); 
	         //DEROutputStream dOut = new DEROutputStream(os); 	            
	         //ASN1StreamParser p = new ASN1StreamParser(sig);
	    	 //ASN1Encodable s = (ASN1Encodable) p.readObject();
		        
             //CertStore certsAndCRLs = CertStore.getInstance("Collection",new CollectionCertStoreParameters(Arrays.asList(chain)),"BC");
            //X509Certificate cert = (X509Certificate)  parameters.getSigningCertificate().getCertificate();
             //gen.addSigner(key, cert, CMSSignedDataGenerator.DIGEST_SHA224);
            //gen.addCertificatesAndCRLs(certsAndCRLs);
			 
			 CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
			 CMSProcessableByteArray msg = new CMSProcessableByteArray(sig);			
	         System.out.println("Content read sucessfully");
	         CertificateFactory cf = CertificateFactory.getInstance("X.509");
	         java.security.cert.Certificate certx = cf.generateCertificate(new ByteArrayInputStream(parameters.getSigningCertificate().getCertificate().getEncoded()));
	         X509Certificate cert = (X509Certificate) certx;
	         System.out.println("Certificate read sucessfully");

	         final CMSProcessableInputStream content = new CMSProcessableInputStream(signedDocument.openStream());
	         //ContentInfo contentInfo = new ContentInfo(contentType, s);
	        // final CMSSignedData signedData = gen.generate(content);
	         
	         //CMSSignedData signature = new CMSSignedData(fileToSign);
	         CMSSignedData signature = new CMSSignedData(new BufferedInputStream(signedDocument.openStream()));
	         Store cs = signature.getCertificates();	         
	         generator.addCertificates(cs);
	         
	         //TODO verificare se serve
	         //ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(key);
	         //generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha256Signer, cert));
	         
	         //System.out.println("Try Signed");
	         //CMSSignedData signed = generator.generate(msg, true);
	         cmsSignedData = new CMSSignedData(sig);
	         System.out.println("Signed");
	        //CMSTypedData msg = new CMSProcessableByteArray(sig);
	        //cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(sig), sig);     

	        SignerInformationStore signers = signature.getSignerInfos();
	        Collection c = signers.getSigners();
	        Iterator it = c.iterator();

	        //the following array will contain the content of xml document
	        byte[] data = null;

	        while (it.hasNext()) {
	             SignerInformation signer = (SignerInformation) it.next();
	             Collection certCollection = cs.getMatches(signer.getSID());
	             Iterator certIt = certCollection.iterator();
	             X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();

	             if(signer.isCounterSignature()){
	            	 System.out.println("Is a counterSigner");
	             }
	             
	             CMSProcessable sc = signature.getSignedContent();
	             data = (byte[]) sc.getContent();
	         }
	        cmsSignedData = signature;
			if(cmsSignedData.getSignedContent().getContent() != null){
				//is a signed document
			}else{
				//is not a signed document
				cmsSignedData = null;
			}
			*/
		}
		return cmsSignedData;
	}
	
	public static boolean checkTheCounterSignature(DSSDocument signedDocument) throws DSSException, IOException, CMSException{
		byte[] sig = IOUtils.toByteArray(signedDocument.openStream());  
		CMSSignedData signature = new CMSSignedData(sig);
        Store cs = signature.getCertificates();
        SignerInformationStore signers = signature.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
		while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection certCollection = cs.getMatches(signer.getSID());
            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

            if(signer.isCounterSignature()){
           	   return true;
            }
            
            //CMSProcessable sc = signature.getSignedContent();
            //data = (byte[]) sc.getContent();
        }
		return false;
	}	
	
	public CAdESSignature getToCountersignSignature(final DSSDocument toCounterSignDocument, final String toCounterSignSignatureId) {
		final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toCounterSignDocument);
		if (!(validator instanceof DocumentValidator)) {
			throw new DSSException("Incompatible signature form!");
		}
		final List<AdvancedSignature> signatures = validator.getSignatures();
		CAdESSignature cadesSignature = null;
		for (final AdvancedSignature signature_ : signatures) {
			final String id = signature_.getId();
			if (toCounterSignSignatureId.equals(id)) {
				cadesSignature = (CAdESSignature) signature_;
				break;
			}
		}
		return cadesSignature;
	}
	
	public DSSDocument nestedSignDocument(final DSSDocument toSignDocument, final CAdESSignatureParameters parameters, SignatureValue signatureValue,PrivateKey privateKey)
			throws DSSException, CertificateEncodingException, OperatorCreationException, CMSException, IOException {
		
		//assertSigningDateInCertificateValidityRange(parameters);
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		//assertSignaturePackaging(packaging);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue.getValue());
		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, true);
		final CMSSignedData originalCmsSignedData = getCmsSignedData(toSignDocument, parameters);
		if ((originalCmsSignedData == null) && SignaturePackaging.DETACHED.equals(packaging) && Utils.isCollectionEmpty(
				parameters.getDetachedContents())) {
			parameters.setDetachedContents(Arrays.asList(toSignDocument));
		}

		final CMSSignedDataGenerator cmsSignedDataGenerator = cmsSignedDataBuilder.createCMSSignedDataGenerator(parameters, customContentSigner,
				signerInfoGeneratorBuilder, originalCmsSignedData);

		final DSSDocument toSignData = getToSignData(toSignDocument, parameters, originalCmsSignedData);
		/*
		final CMSProcessableByteArray content = new CMSProcessableByteArray(DSSUtils.toByteArray(toSignData));		
		final boolean encapsulate = !SignaturePackaging.DETACHED.equals(packaging);
		final CMSSignedData cmsSignedData = CMSUtils.generateCMSSignedData(cmsSignedDataGenerator, content, encapsulate);
		DSSDocument signature = new CMSSignedDocument(cmsSignedData);
		*/
		//=============================================================================================================================
		final CMSProcessableByteArray content = new CMSProcessableByteArray(IOUtils.toByteArray(toSignDocument.openStream())); 		
		final CMSTypedData msg = content;
		List<Certificate> certList = new ArrayList<>();
		for(CertificateToken token : parameters.getCertificateChain()){
			certList.add(token.getCertificate());
		}
		certList.add(parameters.getSigningCertificate().getCertificate()); //Adding the X509 Certificate
		Store myCerts = new JcaCertStore(certList);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		//Initializing the the BC's Signer
		ContentSigner signer = new JcaContentSignerBuilder(parameters.getSignatureAlgorithm().getJCEId()).setProvider("BC").build(privateKey);
		gen.addSignerInfoGenerator(
		            new JcaSignerInfoGeneratorBuilder(
		                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
		                    .build(signer, parameters.getSigningCertificate().getCertificate()));
		//adding the certificate
		gen.addCertificates(myCerts);
		gen.addCRLs(myCerts);
		//Getting the signed data
		final boolean detached = !SignaturePackaging.DETACHED.equals(packaging);
		CMSSignedData sigData = gen.generate(msg, detached);
		parameters.reinitDeterministicId();		
		DSSDocument signature = new CMSSignedDocument(sigData);		
	    //============================================================================================================
		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		if (!SignatureLevel.CAdES_BASELINE_B.equals(signatureLevel)) {
			// true: Only the last signature will be extended
			final SignatureExtension<CAdESSignatureParameters> extension = getExtensionProfile(parameters, true);
			signature = extension.extendSignatures(signature, parameters);
		}
		signature.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
		parameters.reinitDeterministicId();
		
		return signature;		
	}
	
	/**
	 * @param parameters
	 *            set of driving signing parameters
	 * @param onlyLastCMSSignature
	 *            indicates if only the last CSM signature should be extended
	 * @return {@code SignatureExtension} related to the predefine profile
	 */
	private SignatureExtension<CAdESSignatureParameters> getExtensionProfile(final CAdESSignatureParameters parameters, final boolean onlyLastCMSSignature) {
		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		switch (signatureLevel) {
		case CAdES_BASELINE_T:
			return new CAdESLevelBaselineT(tspSource, onlyLastCMSSignature);
		case CAdES_BASELINE_LT:
			return new CAdESLevelBaselineLT(tspSource, certificateVerifier, onlyLastCMSSignature);
		case CAdES_BASELINE_LTA:
			return new CAdESLevelBaselineLTA(tspSource, certificateVerifier, onlyLastCMSSignature);
		default:
			throw new DSSException("Unsupported signature format " + signatureLevel);
		}
	}
	
	/**
	 * This method retrieves the data to be signed. It this data is located within a signature then it is extracted.
	 *
	 * @param toSignDocument
	 *            document to sign
	 * @param parameters
	 *            set of the driving signing parameters
	 * @param originalCmsSignedData
	 *            the signed data extracted from an existing signature or null
	 * @return
	 */
	private DSSDocument getToSignData(final DSSDocument toSignDocument, final CAdESSignatureParameters parameters, final CMSSignedData originalCmsSignedData) {
		final List<DSSDocument> detachedContents = parameters.getDetachedContents();
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			// CAdES only can sign one document
			// (ASiC-S -> the document to sign /
			// ASiC-E -> ASiCManifest)
			return detachedContents.get(0);
		} else {
			if (originalCmsSignedData == null) {
				return toSignDocument;
			} else {
				return getSignedContent(originalCmsSignedData);
			}
		}
	}
	
	/**
	 * This method returns the signed content of CMSSignedData.
	 *
	 * @param cmsSignedData
	 *            the already signed {@code CMSSignedData}
	 * @return the original toSignDocument or null
	 */
	private DSSDocument getSignedContent(final CMSSignedData cmsSignedData) {
		if (cmsSignedData != null) {
			final CMSTypedData signedContent = cmsSignedData.getSignedContent();
			final byte[] documentBytes = (signedContent != null) ? (byte[]) signedContent.getContent() : null;
			final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
			return inMemoryDocument;
		}
		return null;
	}
	
	/**
	 * In case of an enveloping signature if the signed content's content is null then the null is returned.
	 *
	 * @param dssDocument
	 *            {@code DSSDocument} containing the data to be signed or {@code CMSSignedData}
	 * @param parameters
	 *            set of driving signing parameters
	 * @return the {@code CMSSignedData} if the dssDocument is an CMS signed message. Null otherwise.
	 */
	private CMSSignedData getCmsSignedData(final DSSDocument dssDocument, final CAdESSignatureParameters parameters) {
		CMSSignedData cmsSignedData = null;
		if (DSSASN1Utils.isASN1SequenceTag(DSSUtils.readFirstByte(dssDocument))) {
			try {
				cmsSignedData = new CMSSignedData(DSSUtils.toByteArray(dssDocument));
				if (SignaturePackaging.ENVELOPING == parameters.getSignaturePackaging() && cmsSignedData.getSignedContent().getContent() == null) {
					cmsSignedData = null;
				}
			} catch (Exception e) {
				// not a parallel signature
			}
		}
		return cmsSignedData;
	}
}
