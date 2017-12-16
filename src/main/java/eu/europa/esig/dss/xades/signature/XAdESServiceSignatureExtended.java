package eu.europa.esig.dss.xades.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SigningOperation;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.ProfileParameters;
import eu.europa.esig.dss.xades.ProfileParameters.Operation;
import eu.europa.esig.dss.xades.SignatureProfile;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import xades4j.UnsupportedAlgorithmException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesFormatExtenderProfile;
import xades4j.production.XadesSignatureFormatExtender;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.production.XadesTSigningProfile;
import xades4j.properties.AllDataObjsCommitmentTypeProperty;
import xades4j.properties.CounterSignatureProperty;
import xades4j.properties.DataObjectFormatProperty;
import xades4j.properties.UnsignedProperties;
import xades4j.properties.UnsignedSignatureProperty;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.BasicSignatureOptionsProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.MessageDigestEngineProvider;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DefaultTimeStampTokenProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.HttpTimeStampTokenProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyEntryPasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyStorePasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.SigningCertSelector;
import xades4j.providers.impl.TSAHttpData;
import xades4j.utils.DOMHelper;

/**
 * 
 * with old dss 4.6.0
 * 
 * https://github.com/arhs/sd-dss/blob/master/apps/dss/core/dss-document/src/main/java/eu/europa/ec/markt/dss/signature/cades/CAdESService.java
 * 
 * wiht Xades4J
 * http://www.anjuke.tech/questions/4964741/how-to-verify-for-counter-signed-xml-document
 * http://youcodewiki.blogspot.it/2010/04/xml-xades4j-how-to-add-countersign.html
 * https://github.com/luisgoncalves/xades4j/issues/116
 * https://gist.github.com/JohnnyJosep/29cd545db3d0b7abd23279b56d4db194
 */
public class XAdESServiceSignatureExtended extends XAdESService{
	
	private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(XAdESServiceSignatureExtended.class);
	
	protected static final String TSP_SERVER_DEFAULT = "https://freetsa.org/tsr";	
	
	public XAdESServiceSignatureExtended(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);		
	}
		
	/**
	 * This method countersigns a signature identified through its SignerId
	 *
	 * @param toCounterSignDocument the original signature document containing the signature to countersign
	 * @param parameters            the signature parameters
	 * @param selector              the SignerId identifying the signature to countersign
	 * @return the updated signature document, in which the countersignature has been embedded
	 * @throws IOException 
	 * @throws DSSException 
	 * @throws CMSException 
	 * @throws CertificateEncodingException 
	 * @throws CertificateException 
	 * @throws OperatorCreationException 
	 */
	/*
	public DSSDocument counterSignDocument(
			final DSSDocument toCounterSignDocument, final XAdESSignatureParameters parameters,
			SignatureValue signatureValue, SignerId selector) 
					throws DSSException, CertificateEncodingException, OperatorCreationException, IOException, CMSException {

		if (toCounterSignDocument == null) {
			throw new DSSException("toCounterSignDocument");
		}
		if (parameters == null) {
			throw new DSSException("The signature parameters is empty or NULL");
		}
		if (parameters.getSignatureLevel() == null) {
			throw new DSSException("The signatureLevel is NULL");
		}
		
		//final SignatureTokenConnection signingToken = parameters.getSigningToken();
		//if (signingToken == null) {
		//	throw new DSSException("The token connection is null");
		//}
		//final String toCounterSignSignatureId = parameters.getToCounterSignSignatureId();
		final String toCounterSignSignatureId = selector.toString();	
		//TODO capire come mai non prende il cmisdatasign
		CMSSignedData originalCmsSignedData = getCmsSignedData(toCounterSignDocument,parameters);
		
	    // create the signed-data object
		// set up the generator

        ////CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ////gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withRSA", parameters.getSigningCertificate()., parameters.getSigningCertificate().getCertificate()t));
        ////gen.addCertificates(certs);
        ////CMSTypedData data = new CMSProcessableByteArray("Hello World!".getBytes());
        ////CMSSignedData signed = gen.generate(data);        
        /////// recreate
        ////signed = new CMSSignedData(data, signed.getEncoded());
		
		
		SignerInformationStore signerInfos = originalCmsSignedData.getSignerInfos();
		SignerInformation signerInformation = signerInfos.get(selector);
		
		//cms.getSignerInfos().get(id)
		
		if (toCounterSignSignatureId.isEmpty()) {
			throw new DSSException("There is no provided signature id to countersign!");
		}
		final XAdESSignature xadesSignature = getToCountersignSignature(toCounterSignDocument, toCounterSignSignatureId);
		if (xadesSignature == null) {
			throw new DSSException("The signature to countersign not found!");
		}
		final Node signatureValueNode = xadesSignature.getSignatureValue();
		if (signatureValueNode == null) {
			throw new DSSException("signature-value");
		}
		final String signatureValueId = DssUtilsService.getIDIdentifier((Element) signatureValueNode);
		if (signatureValueId.isEmpty()) {
			throw new DSSException("There is no signature-value id to countersign!");
		}
		//parameters.setToCounterSignSignatureValueId(signatureValueId);

		final CounterSignatureBuilder counterSignatureBuilder = new CounterSignatureBuilder(toCounterSignDocument, xadesSignature, parameters, certificateVerifier);
		//final byte[] dataToSign = counterSignatureBuilder.build();
		//DSSDocument document = new InMemoryDocument(counterSignatureBuilder.build());
		//final ToBeSigned dataToSign = getDataToSign(document,parameters);
		
		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		//final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getgetPrivateKeyEntry();

		//byte[] counterSignatureValue = signingToken.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);
		SignatureValue counterSignatureValue = signatureValue;
				
		final DSSDocument counterSignedDocument = counterSignatureBuilder.signDocument(counterSignatureValue);
		//		final XMLDocumentValidator xmlDocumentValidator = (XMLDocumentValidator) validator;
		//		final Document rootElement = xmlDocumentValidator.getRootElement();
		//		final byte[] bytes = DSSXMLUtils.transformDomToByteArray(rootElement);
		//		final InMemoryDocument inMemoryDocument = new InMemoryDocument(bytes);
		return counterSignedDocument;
	}
    */
	public XAdESSignature getToCountersignSignature(final DSSDocument toCounterSignDocument, final String toCounterSignSignatureId) {

		final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toCounterSignDocument);
		if (!(validator instanceof XMLDocumentValidator)) {
			throw new DSSException("Incompatible signature form!");
		}
		final List<AdvancedSignature> signatures = validator.getSignatures();
		XAdESSignature xadesSignature = null;
		for (final AdvancedSignature signature_ : signatures) {
			final String id = signature_.getId();
			if (toCounterSignSignatureId.equals(id)) {
				xadesSignature = (XAdESSignature) signature_;
				break;
			}
		}
		return xadesSignature;
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
	 * @throws OperatorCreationException 
	 * @throws CMSException 
	 * @throws CertificateEncodingException 
	 */
	private CMSSignedData getCmsSignedData(final DSSDocument dssDocument, final XAdESSignatureParameters parameters) throws IOException, OperatorCreationException, CMSException, CertificateEncodingException {
		Security.addProvider(new BouncyCastleProvider());  
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
		}else{
			//https://github.com/joschi/cryptoworkshop-bouncycastle/blob/master/src/main/java/cwguide/BcSignedDataExample.java
			List<Certificate> certificates = new ArrayList<>();
			for(CertificateToken certificateToken : parameters.getCertificateChain()){
				certificates.add(certificateToken.getCertificate());
			}		
			org.bouncycastle.asn1.x509.Certificate bCertificate = org.bouncycastle.asn1.x509.Certificate.getInstance(parameters.getSigningCertificate().getCertificate().getEncoded());
			X509CertificateHolder cert = new X509CertificateHolder(bCertificate);
			PrivateKey jKey = null; //TODO
			AsymmetricKeyParameter key = PrivateKeyFactory.createKey(jKey.getEncoded());
			
			Store certs = new CollectionStore(certificates);
	        // set up the generator
	        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	        AlgorithmIdentifier sigAlg = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
	        AlgorithmIdentifier digAlg = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlg);
	        gen.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider()).build(new BcRSAContentSignerBuilder(sigAlg, digAlg).build(key), cert));
	        gen.addCertificates(certs);
	        
	        // create the signed-data object
	        CMSTypedData data = new CMSProcessableByteArray(DSSUtils.toByteArray(dssDocument));
	        cmsSignedData = gen.generate(data);
		}
		return cmsSignedData;
	}

	/*
	public DSSDocument counterSignDocument(final DSSDocument toCounterSignDocument, final SignatureParameters parameters) throws DSSException {

		if (toCounterSignDocument == null) {
			throw new DSSNullException(DSSDocument.class, "toCounterSignDocument");
		}
		if (parameters == null) {
			throw new DSSNullException(SignatureParameters.class);
		}
		if (parameters.getSignatureLevel() == null) {
			throw new DSSNullException(SignatureLevel.class);
		}
		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {
			throw new DSSNullException(SignatureTokenConnection.class);
		}
		final String toCounterSignSignatureId = parameters.getToCounterSignSignatureId();
		if (DSSUtils.isBlank(toCounterSignSignatureId)) {
			throw new DSSException("There is no provided signature id to countersign!");
		}
		final XAdESSignature xadesSignature = getToCountersignSignature(toCounterSignDocument, toCounterSignSignatureId);
		if (xadesSignature == null) {
			throw new DSSException("The signature to countersign not found!");
		}
		final Node signatureValueNode = xadesSignature.getSignatureValue();
		if (signatureValueNode == null) {
			throw new DSSNullException(Node.class, "signature-value");
		}
		final String signatureValueId = DSSXMLUtils.getIDIdentifier((Element) signatureValueNode);
		if (DSSUtils.isBlank(toCounterSignSignatureId)) {
			throw new DSSException("There is no signature-value id to countersign!");
		}
		parameters.setToCounterSignSignatureValueId(signatureValueId);

		final CounterSignatureBuilder counterSignatureBuilder = new CounterSignatureBuilder(toCounterSignDocument, xadesSignature, parameters, certificateVerifier);
		final byte[] dataToSign = counterSignatureBuilder.build();

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getPrivateKeyEntry();

		byte[] counterSignatureValue = signingToken.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);

		final DSSDocument counterSignedDocument = counterSignatureBuilder.signDocument(counterSignatureValue);
		//		final XMLDocumentValidator xmlDocumentValidator = (XMLDocumentValidator) validator;
		//		final Document rootElement = xmlDocumentValidator.getRootElement();
		//		final byte[] bytes = DSSXMLUtils.transformDomToByteArray(rootElement);
		//		final InMemoryDocument inMemoryDocument = new InMemoryDocument(bytes);
		return counterSignedDocument;
	}

	private XAdESSignature getToCountersignSignature(final DSSDocument toCounterSignDocument, final String toCounterSignSignatureId) {

		final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toCounterSignDocument);
		if (!(validator instanceof XMLDocumentValidator)) {
			throw new DSSException("Incompatible signature form!");
		}
		final List<AdvancedSignature> signatures = validator.getSignatures();
		XAdESSignature xadesSignature = null;
		for (final AdvancedSignature signature_ : signatures) {

			final String id = signature_.getId();
			if (toCounterSignSignatureId.equals(id)) {

				xadesSignature = (XAdESSignature) signature_;
				break;
			}
		}
		return xadesSignature;
	}
	 */
	//==================================================================================================================================================================
	/*
	@Deprecated
	public DSSDocument counterSignDocument(final DSSDocument toCounterSignDocument, final XAdESSignatureParameters parameters,
			SignatureValue signatureValue,PrivateKey privateKey) 		
					throws DSSException {
		DSSDocument dssDocument = null;
		File fileToSign = null;
		boolean isTemp = false;
		try {
			X509Certificate signingCertificate = parameters.getSigningCertificate().getCertificate();			
			if(toCounterSignDocument.getAbsolutePath() != null){
				fileToSign = new File(toCounterSignDocument.getAbsolutePath());
			}else{
				String name = toCounterSignDocument.getName();
				if(name == null || name.isEmpty()){name=new SimpleDateFormat("yyyyMMddHHmmss").format(Calendar.getInstance().getTime());}
				fileToSign = File.createTempFile(name, ".tmp");
				FileUtils.writeByteArrayToFile(fileToSign,IOUtils.toByteArray(toCounterSignDocument.openStream()));
				isTemp =true;
			}
			//InputStream dataToSign = toCounterSignDocument.openStream();
			String xadesSchema = "xades:SigningCertificate";
			String digestAlgorithm = parameters.getDigestAlgorithm().getName();
			String tspServer = TSP_SERVER_DEFAULT;
			TSPSource source = super.tspSource;
			PrivateKey pk = privateKey;		
			DataToSign dataToSign2 = new DataToSign(fileToSign);
		
			Document doc = counterSign(signingCertificate, dataToSign2, pk, xadesSchema, digestAlgorithm, new URL(TSP_SERVER_DEFAULT));
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			Source xmlSource = new DOMSource(doc);
			Result outputTarget = new StreamResult(outputStream);
			TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
			InputStream is = new ByteArrayInputStream(outputStream.toByteArray());
			dssDocument = new InMemoryDocument(is);
		} catch (Exception e) {
			throw new DSSException(e);
		}finally{
			if(isTemp){
				FileUtils.deleteQuietly(fileToSign);
			}
		}
		return dssDocument;
	}
	*/
	/*
	 @Deprecated
	 public static Document counterSign(X509Certificate certificadoFirma, DataToSign xml, PrivateKey pk, String xadesSchema, String digitalSignatureAlgorithm, URL urlTSA)
	    throws Exception
	  {
	    return counterSign(certificadoFirma, xml, null, pk, digitalSignatureAlgorithm, urlTSA, xadesSchema);
	  }
	
	  @Deprecated
	  public static Document counterSign(X509Certificate certificadoFirma, DataToSign xml, X509Certificate certificadoContraFirma, PrivateKey pk, String digitalSignatureAlgorithm, URL urlTSA, String xadesSchema)throws DSSException
	  {
	    try
	    {
	      Document doc = xml.getDocument();
	      if (doc == null) {
	        try {
	          InputStream is = xml.getInputStream();
	          if (is != null) {
	            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	            dbf.setNamespaceAware(true);
	            DocumentBuilder db = dbf.newDocumentBuilder();
	            db.setErrorHandler(new IgnoreAllErrorHandler());
	            InputSource isour = new InputSource(is);
	            String encoding = xml.getXMLEncoding();
	            isour.setEncoding(encoding);
	            doc = db.parse(isour);
	          }
	        } catch (IOException ex) {
	          throw new DSSException("libreriaxades.firmaxml.error50");
	        }
	
	      }
	
	      Node nodePadreNodoFirmar = null;
	      if (certificadoContraFirma != null) {
	        nodePadreNodoFirmar = buscarNodoAFirmar(doc, certificadoContraFirma);
	        if (nodePadreNodoFirmar == null) {
	          logger.info("libreriaxades.firmaxml.error33");
	          throw new DSSException("libreriaxades.firmaxml.error51");
	        }
	      }
	
	      if (nodePadreNodoFirmar == null)
	      {
	        NodeList list = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
	        if (list.getLength() < 1) {
	          logger.info("libreriaxades.firmaxml.error33");
	          throw new DSSException("libreriaxades.firmaxml.error51");
	        }
	        nodePadreNodoFirmar = list.item(list.getLength() - 1);
	      }
	
	      String idSignatureValue = null;
	      Element padreNodoFirmar = null;
	      if ((nodePadreNodoFirmar != null) && (nodePadreNodoFirmar.getNodeType() == 1)) {
	        padreNodoFirmar = (Element)nodePadreNodoFirmar;
	        ArrayList listElements = DssUtilsCounterSign.obtenerNodos(padreNodoFirmar, 2, new NombreNodo("http://www.w3.org/2000/09/xmldsig#", "SignatureValue"));
	        if (listElements.size() != 1)
	        {
	          logger.info("libreriaxades.firmaxml.error33");
	          throw new DSSException("libreriaxades.firmaxml.error51");
	        }
	        idSignatureValue = ((Element)listElements.get(0)).getAttribute("Id");
	
	        if (idSignatureValue == null)
	        {
	          logger.info("libreriaxades.firmaxml.error33");
	          throw new DSSException("libreriaxades.firmaxml.error51");
	        }
	
	      }
	
	      ArrayList listElements = DssUtilsCounterSign.obtenerNodos(padreNodoFirmar, 2, "QualifyingProperties");
	      if (listElements.size() != 1)
	      {
	        logger.info("libreriaxades.firmaxml.error33");
	        throw new DSSException("libreriaxades.firmaxml.error51");
	      }
	      String esquemaOrigen = ((Element)listElements.get(0)).getNamespaceURI();
	      NodeList nodosUnsigSigProp = padreNodoFirmar.getElementsByTagNameNS(esquemaOrigen, "UnsignedSignatureProperties");
	
	      Element nodoRaiz = null;
	      if ((nodosUnsigSigProp != null) && (nodosUnsigSigProp.getLength() != 0)) {
	        nodoRaiz = (Element)nodosUnsigSigProp.item(0);
	      } else {
	        NodeList nodosQualifying = padreNodoFirmar.getElementsByTagNameNS(esquemaOrigen, "QualifyingProperties");
	
	        if ((nodosQualifying != null) && (nodosQualifying.getLength() != 0)) {
	          Element nodoQualifying = (Element)nodosQualifying.item(0);
	          Element unsignedProperties = null;
	          if (nodoQualifying.getPrefix() != null) {
	            unsignedProperties = doc.createElementNS(esquemaOrigen, nodoQualifying.getPrefix() + ":" + "UnsignedProperties");
	
	            nodoRaiz = doc.createElementNS(esquemaOrigen, nodoQualifying.getPrefix() + ":" + "UnsignedSignatureProperties");
	          }
	          else {
	            unsignedProperties = doc.createElementNS(esquemaOrigen, "UnsignedProperties");
	
	            nodoRaiz = doc.createElementNS(esquemaOrigen, "UnsignedSignatureProperties");
	          }
	
	          unsignedProperties.appendChild(nodoRaiz);
	          nodosQualifying.item(0).appendChild(unsignedProperties);
	        } else {
	          throw new DSSException("libreriaxades.firmaxml.error52");
	        }
	      }
	
	      Element counterSignature = null;
	      if (nodoRaiz.getPrefix() != null) {
	        counterSignature = doc.createElementNS(esquemaOrigen, nodoRaiz.getPrefix() + ":" + "CounterSignature");
	      }
	      else {
	        counterSignature = doc.createElementNS(esquemaOrigen, "CounterSignature");
	      }
	      nodoRaiz.appendChild(counterSignature);
	
	      Attr counterSignatureAttrib = doc.createAttributeNS(null, "Id");
	      String counterSignatureId = DssUtilsCounterSign.newID(doc, "CounterSignature-");
	      counterSignatureAttrib.setValue(counterSignatureId);
	      counterSignature.getAttributes().setNamedItem(counterSignatureAttrib);
	
	      xml.setDocument(doc);
	
	      AbstractObjectToSign obj = null;
	      //if (XAdESSignature.DEFAULT_XADES_SCHEMA_URI.equals(xadesSchema))
	      if (XAdESNamespaces.XAdES132.equals(xadesSchema))
	        obj = new SignObjectToSign(idSignatureValue);
	      else {
	        obj = new InternObjectToSign(idSignatureValue);
	      }
	      xml.addObject(new ObjectToSign(obj, null, null, null, null));
	
	      xml.setParentSignNode(counterSignatureId);
	      FirmaXML firma = new FirmaXML();
	      if (urlTSA != null) {
	        firma.setTSA(urlTSA.toString());
	      }
	      Object[] res = firma.signFile(certificadoFirma, xml, pk, DssUtilsCounterSign.getXAdESDigitalSignatureAlgorithm(digitalSignatureAlgorithm), null);
	
	      doc = (Document)res[0];
	
	      counterSignature = DssUtilsCounterSign.getElementById(doc, counterSignatureId);
	      counterSignature.removeAttribute("Id");
	
	      return doc;
	    } catch (Exception e) {
	      throw new DSSException(e);
	    }
	  }
	
	  private static Node buscarNodoAFirmar(Document doc, X509Certificate certificadoContraFirma)
	  {
	    XPathFactory factory = XPathFactory.newInstance();
	    XPath xpath = factory.newXPath();
	    NodeList certificateNodes;
	    try
	    {
	      XPathExpression expr = xpath.compile("//*[local-name()='Signature']/*[local-name()='KeyInfo']/*[local-name()='X509Data']/*[local-name()='X509Certificate']");
	      certificateNodes = (NodeList)expr.evaluate(doc, XPathConstants.NODESET);
	    } catch (Exception e) {
	      logger.info("[ContraFirmaXML.buscarNodoAFirmar]::Error inesperado", e);
	      return null;
	    }
	
	    if ((certificateNodes == null) || (certificateNodes.getLength() == 0)) {
	      logger.info("[ContraFirmaXML.buscarNodoAFirmar]::Falta el elemento 'X509Certificate' de la firma, con lo que no es posible obtener la cadena de confianza de un certificado que no existe");
	      return null;
	    }
	
	    for (int i = 0; i < certificateNodes.getLength(); i++) {
	      try {
	        X509Certificate x509Cert = DssUtilsCounterSign.getCertificate(Base64.decodeBase64(certificateNodes.item(i).getTextContent()));
	        if (x509Cert.equals(certificadoContraFirma))
	          return certificateNodes.item(i).getParentNode().getParentNode().getParentNode();
	      }
	      catch (Exception e) {
	        logger.info("[ContraFirmaXML.buscarNodoAFirmar]::Error inesperado", e);
	      }
	    }
	
	    return null;
	  }
		*/
	//================================================================================================
	
	public DSSDocument counterSignDocument(
			final DSSDocument toCounterSignDocument, final XAdESSignatureParameters parameters,
			SignatureValue signatureValue, File keyStoreFile,String keyStoreType,final String keyStorePassword) 
					throws DSSException {
		
		if (toCounterSignDocument == null) {
			throw new DSSException("toCounterSignDocument");
		}
		if (parameters == null) {
			throw new DSSException("The signature parameters is empty or NULL");
		}
		if (parameters.getSignatureLevel() == null) {
			throw new DSSException("The signatureLevel is NULL");
		}
		
		//InputStream dataToSign = toCounterSignDocument.openStream();
		String xadesSchema = "xades:SigningCertificate";
		String digestAlgorithm = parameters.getDigestAlgorithm().getName();
		String tspServer = TSP_SERVER_DEFAULT;
		TSPSource source = super.tspSource;
		PrivateKey privateKey = null;
		String mimetype = eu.europa.esig.dss.MimeType.XML.getMimeTypeString();
				
		DSSDocument dssDocument = null;
		File fileToSign = null;
		boolean isTemp = false;
		try {
			java.security.cert.X509Certificate signingCertificate = parameters.getSigningCertificate().getCertificate();			
			if(toCounterSignDocument.getAbsolutePath() != null){
				fileToSign = new File(toCounterSignDocument.getAbsolutePath());
			}else{
				String name = toCounterSignDocument.getName();
				if(name == null || name.isEmpty()){name=new SimpleDateFormat("yyyyMMddHHmmss").format(Calendar.getInstance().getTime());}
				fileToSign = File.createTempFile(name, ".tmp");
				FileUtils.writeByteArrayToFile(fileToSign,IOUtils.toByteArray(toCounterSignDocument.openStream()));
				isTemp =true;
			}
			
			//INPUTSTREAM TO XML DOC
		    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		    dbf.setValidating(false);
		    dbf.setIgnoringComments(false);
		    dbf.setIgnoringElementContentWhitespace(true);
		    dbf.setNamespaceAware(true);
		    // dbf.setCoalescing(true);
		    // dbf.setExpandEntityReferences(true);
	        DocumentBuilder db = dbf.newDocumentBuilder();
	        db.setEntityResolver(new NullResolver());
	        // db.setErrorHandler( new MyErrorHandler());
			Document doc = db.parse(toCounterSignDocument.openStream());
	
			SigningCertSelector signingCertSelector = new SigningCertSelector() {				
				@Override
				public java.security.cert.X509Certificate selectCertificate(
						List<java.security.cert.X509Certificate> availableCertificates) {
						 return availableCertificates.get(0);				    
				}
			};
			
			KeyingDataProvider kp = new FileSystemKeyStoreKeyingDataProvider(
					keyStoreType,keyStoreFile.getAbsolutePath(), 
					signingCertSelector, new DirectPasswordProvider(keyStorePassword),
					new DirectPasswordProvider(keyStorePassword), true); 	
			//KeyingDataProvider kp = new StaticKeyingDataProvider(certificateChain, privateKey);
			
			BasicSignatureOptionsProvider bop=new BasicSignatureOptionsProvider() {
		        public boolean signSigningCertificate() {return false;}
		        public boolean includeSigningCertificate() {return true;}
		        public boolean includePublicKey() {return true;}
		    };
			
			/*
			Element elemToSign = doc.getDocumentElement();
	        XadesBesSigningProfile profile = new XadesBesSigningProfile(kp);
	        final XadesSigner counterSigner = profile.newSigner();
	        profile.withSignaturePropertiesProvider(new SignaturePropertiesProvider()
	        {
	            @Override
	            public void provideProperties(
	                    SignaturePropertiesCollector signedPropsCol)
	            {
	                signedPropsCol.addCounterSignature(new CounterSignatureProperty(counterSigner));
	                signedPropsCol.setSignerRole(new SignerRoleProperty("CounterSignature maniac"));
	            }
	        });	               
	        XadesSigner signer = profile.newSigner();
	        DataObjectDesc obj1 = new DataObjectReference('#' + elemToSign.getAttribute("Id")).withTransform(new EnvelopedSignatureTransform());
	        SignedDataObjects dataObjs = new SignedDataObjects().withSignedDataObject(obj1);
	        signer.sign(dataObjs, elemToSign);        
	        // get inner signatureElement from doc
	        NodeList signatureList = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE);
	        Element signatureElement = (Element)signatureList.item(signatureList.getLength() - 1);
			XadesSignatureFormatExtender extender = new XadesFormatExtenderProfile().getFormatExtender();
			XMLSignature sig = new XMLSignature(signatureElement, signatureElement.getOwnerDocument().getBaseURI());
			Collection<UnsignedSignatureProperty> usp = new ArrayList<UnsignedSignatureProperty>(1);
			usp.add(new CounterSignatureProperty(counterSigner));
			extender.enrichSignature(sig, new UnsignedProperties(usp));
		    */
			
			//CounterSigning
			Element elemToSign = doc.getDocumentElement();
			DOMHelper.useIdAsXmlId(elemToSign);
			
			XadesSigningProfile profile = new XadesBesSigningProfile(kp);
					////.withTimeStampTokenProvider(CertumFreeTimeStampProvider.class)
					//.withBasicSignatureOptionsProvider(bop);
			
			 // Get the specific signature algorithm for the key's algorithm.
			AlgorithmsProviderEx algorithmsProvider = new DefaultAlgorithmsProviderEx();
	        Algorithm sigAlgUri = algorithmsProvider.getSignatureAlgorithm("RSA");
	        if (null == sigAlgUri)
	            throw new NullPointerException("Signature algorithm URI not provided");

	        Algorithm canonAlgUri = algorithmsProvider.getCanonicalizationAlgorithmForSignature();
	        if (null == canonAlgUri)
	            throw new NullPointerException("Canonicalization algorithm URI not provided");

	        final String digestAlgUri = algorithmsProvider.getDigestAlgorithmForDataObjsReferences();
	        if (null == digestAlgUri)
        		throw new NullPointerException("Digest algorithm URI not provided");
			
			profile.withDigestEngineProvider(new SHA256MessageDigestEngineProvider());
			
	        /*
			XadesSigner signer = profile.newSigner(); 
			DataObjectReference desc = (DataObjectReference) new DataObjectReference("")
				    .withDataObjectFormat(new DataObjectFormatProperty(mimetype, "UTF-8"))
				    .withTransform(new EnvelopedSignatureTransform());
			
			SignedDataObjects dataObjects = new SignedDataObjects(desc)
				    .withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfOrigin());
			*/
	        
			//Sign the document (not necessary)
			//XadesSignatureResult sign = signer.sign(dataObjects, elemToSign);
			//Element signatureElement = sign.getSignature().getElement();
			
			//This is not work Digest in authenticationAttribute it's not correct
			//NodeList signatureList = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE);
			//Element signatureElement = (Element)signatureList.item(signatureList.getLength() - 1);			

			//DOC TO STRING
			/*
			DOMSource domSource = new DOMSource(doc);
			StringWriter writer = new StringWriter();
			StreamResult result = new StreamResult(writer);
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			transformer.transform(domSource, result);						
			String signed_xml = writer.toString();
			*/
        
			//EXTENDER	
			XadesSigner counterSigner = profile.newSigner();
		    XadesFormatExtenderProfile p = new XadesFormatExtenderProfile();		    	   
			XadesSignatureFormatExtender extender = p.getFormatExtender();
				
			logger.debug("Tag do podpisu:"+elemToSign.getNodeName());		
			XMLSignature sig = new XMLSignature(elemToSign, elemToSign.getOwnerDocument().getBaseURI());		
			// .withTransform(new ExclusiveCanonicalXMLWithoutComments());

			Collection<UnsignedSignatureProperty> usp = new ArrayList<UnsignedSignatureProperty>(1);
			usp.add(new CounterSignatureProperty(counterSigner));
	
			extender.enrichSignature(sig, new UnsignedProperties(usp));
		    
		    //XML DOC TO INPUTSTREAM			
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			Source xmlSource = new DOMSource(doc);
			Result outputTarget = new StreamResult(outputStream);
			TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
			ByteArrayInputStream is = new ByteArrayInputStream(outputStream.toByteArray());			
			dssDocument = new InMemoryDocument(is);			
		} catch (Exception e) {
			throw new DSSException(e);
		}finally{
			if(isTemp){
				FileUtils.deleteQuietly(fileToSign);
			}
		}
		return dssDocument;

	}

	 private class DirectPasswordProvider implements KeyStorePasswordProvider, KeyEntryPasswordProvider
	 {
		 private char[] password;
		
		 public DirectPasswordProvider(String password)
		 {
		     this.password = password.toCharArray();
		 }
		
		 @Override
		 public char[] getPassword()
		 {
		     return password;
		 }

		@Override
		public char[] getPassword(String entryAlias, java.security.cert.X509Certificate entryCert) {			
			return password;
		}
	}
	 
	 private class SHA256MessageDigestEngineProvider implements MessageDigestEngineProvider{				
			@Override
			public MessageDigest getEngine(String digestAlgorithmURI) throws UnsupportedAlgorithmException {					
				try {
					//return MessageDigest.getInstance(digestAlgUri);
					return MessageDigest.getInstance("SHA-256");
				} catch (NoSuchAlgorithmException e) {
					 throw new UnsupportedAlgorithmException("","",e);
				}
			}
	}
	 
	 private class FirstCertificateSelector implements SigningCertSelector
	 {
	     @Override
	     public X509Certificate selectCertificate(
	             List<X509Certificate> availableCertificates)
	     {
	         return availableCertificates.get(0);
	     }
	 }
	 
	private class NullResolver implements EntityResolver {
	  public InputSource resolveEntity(String publicId, String systemId) throws SAXException,
	      IOException {
	    return new InputSource(new StringReader(""));
	  }
	}
	
	public DSSDocument nestedSignDocument(final DSSDocument toSignDocument, final XAdESSignatureParameters parameters,
			SignatureValue signatureValue, File keyStoreFile,String keyStoreType,final String keyStorePassword, 
			String tspServer,String tspUsernmae,String tspPassword)
			throws DSSException, CertificateEncodingException, OperatorCreationException, CMSException, IOException {
		
		if (parameters.getSignatureLevel() == null) {
			throw new NullPointerException();
		}
		assertSigningDateInCertificateValidityRange(parameters);
		parameters.getContext().setOperationKind(Operation.SIGNING);
		//SignatureProfile profile;
		//final ProfileParameters context = parameters.getContext();
		//if (context.getProfile() != null) {
		//	profile = context.getProfile();
		//} else {
		//	profile = new XAdESLevelBaselineB(certificateVerifier);
		//}
		////final DSSDocument signedDoc = profile.signDocument(toSignDocument, parameters, signatureValue.getValue());
		//=============================================================================================================================
		DSSDocument signedDoc = null;
		try {
			//INPUTSTREAM TO XML DOC
		    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		    dbf.setValidating(false);
		    dbf.setIgnoringComments(false);
		    dbf.setIgnoringElementContentWhitespace(true);
		    dbf.setNamespaceAware(true);
		    // dbf.setCoalescing(true);
		    // dbf.setExpandEntityReferences(true);
	        DocumentBuilder db = dbf.newDocumentBuilder();
	        db.setEntityResolver(new NullResolver());
	        // db.setErrorHandler( new MyErrorHandler());
			Document doc = db.parse(toSignDocument.openStream());
	
			SigningCertSelector signingCertSelector = new SigningCertSelector() {				
				@Override
				public java.security.cert.X509Certificate selectCertificate(
						List<java.security.cert.X509Certificate> availableCertificates) {
						 return availableCertificates.get(0);				    
				}
			};
			
			KeyingDataProvider kp = new FileSystemKeyStoreKeyingDataProvider(
					keyStoreType,keyStoreFile.getAbsolutePath(), 
					signingCertSelector, new DirectPasswordProvider(keyStorePassword),
					new DirectPasswordProvider(keyStorePassword), true); 	
			//KeyingDataProvider kp = new StaticKeyingDataProvider(certificateChain, privateKey);
			
			BasicSignatureOptionsProvider bop=new BasicSignatureOptionsProvider() {
		        public boolean signSigningCertificate() {return false;}
		        public boolean includeSigningCertificate() {return true;}
		        public boolean includePublicKey() {return true;}
		    };
		
			Element elemToSign = doc.getDocumentElement();
			DOMHelper.useIdAsXmlId(elemToSign);
			
			XadesSigningProfile profile = new XadesBesSigningProfile(kp);
			TSAHttpData tsaHttpData = null;
			if(tspUsernmae!=null && !tspUsernmae.isEmpty() && tspPassword != null && !tspPassword.isEmpty()){
				tsaHttpData = new TSAHttpData(tspServer,tspUsernmae,tspPassword);
			}else{
				tsaHttpData = new TSAHttpData(tspServer);
			}
			if(parameters.getSignatureLevel().equals(SignatureLevel.XAdES_BASELINE_T) || 
					parameters.getSignatureLevel().equals(SignatureLevel.XAdES_BASELINE_LT)){
					profile.withTimeStampTokenProvider(new HttpTimeStampTokenProvider(
							new SHA256MessageDigestEngineProvider(),tsaHttpData));
					//.withBasicSignatureOptionsProvider(bop);
			}
			 // Get the specific signature algorithm for the key's algorithm.
			AlgorithmsProviderEx algorithmsProvider = new DefaultAlgorithmsProviderEx();
	        Algorithm sigAlgUri = algorithmsProvider.getSignatureAlgorithm("RSA");
	        if (null == sigAlgUri)
	            throw new NullPointerException("Signature algorithm URI not provided");

	        Algorithm canonAlgUri = algorithmsProvider.getCanonicalizationAlgorithmForSignature();
	        if (null == canonAlgUri)
	            throw new NullPointerException("Canonicalization algorithm URI not provided");

	        final String digestAlgUri = algorithmsProvider.getDigestAlgorithmForDataObjsReferences();
	        if (null == digestAlgUri)
        		throw new NullPointerException("Digest algorithm URI not provided");
			
			profile.withDigestEngineProvider(new SHA256MessageDigestEngineProvider());				        
			//Sign the document
			XadesSigner signer = profile.newSigner(); 
			DataObjectReference desc = (DataObjectReference) new DataObjectReference("")
				    .withDataObjectFormat(new DataObjectFormatProperty(MimeType.XML.getMimeTypeString(), "UTF-8"))
				    .withTransform(new EnvelopedSignatureTransform());
			
			SignedDataObjects dataObjects = new SignedDataObjects(desc)
				    .withCommitmentType(AllDataObjsCommitmentTypeProperty.proofOfOrigin());
			  
			XadesSignatureResult sign = signer.sign(dataObjects, elemToSign);
			//Element signatureElement = sign.getSignature().getElement();
			
			//This is not work Digest in authenticationAttribute it's not correct
			//NodeList signatureList = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE);
			//Element signatureElement = (Element)signatureList.item(signatureList.getLength() - 1);			


			//EXTENDER	
			//XadesSigner counterSigner = profile.newSigner();
		    //XadesFormatExtenderProfile p = new XadesFormatExtenderProfile();		    	   
			//XadesSignatureFormatExtender extender = p.getFormatExtender();				
			//logger.debug("Tag do podpisu:"+elemToSign.getNodeName());		
			//XMLSignature sig = new XMLSignature(elemToSign, elemToSign.getOwnerDocument().getBaseURI());		
			// .withTransform(new ExclusiveCanonicalXMLWithoutComments());

			//Collection<UnsignedSignatureProperty> usp = new ArrayList<UnsignedSignatureProperty>(1);
			//usp.add(new CounterSignatureProperty(counterSigner));	
			//extender.enrichSignature(sig, new UnsignedProperties(usp));
		    
		    //XML DOC TO INPUTSTREAM			
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			Source xmlSource = new DOMSource(doc);
			Result outputTarget = new StreamResult(outputStream);
			TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
			ByteArrayInputStream is = new ByteArrayInputStream(outputStream.toByteArray());			
			signedDoc = new InMemoryDocument(is);			
		} catch (Exception e) {
			throw new DSSException(e);
		}
		//============================================================================================================
		final SignatureExtension<XAdESSignatureParameters> extension = getExtensionProfile(parameters);
		if (extension != null) {
			if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging()) && Utils.isCollectionEmpty(parameters.getDetachedContents())) {
				List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
				detachedContents.add(toSignDocument);
				parameters.setDetachedContents(detachedContents);
			}
			final DSSDocument dssExtendedDocument = extension.extendSignatures(signedDoc, parameters);
			// The deterministic id is reset between two consecutive signing operations. It prevents having two
			// signatures with the same Id within the
			// same document.
			parameters.reinitDeterministicId();
			dssExtendedDocument.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));
			return dssExtendedDocument;
		}
		parameters.reinitDeterministicId();
		signedDoc.setName(DSSUtils.getFinalFileName(toSignDocument, SigningOperation.SIGN, parameters.getSignatureLevel()));

		return signedDoc;	
	}
	
	/**
	 * The choice of profile according to the passed parameter.
	 *
	 * @param parameters
	 * @return
	 */
	private SignatureExtension<XAdESSignatureParameters> getExtensionProfile(final XAdESSignatureParameters parameters) {
		switch (parameters.getSignatureLevel()) {
		case XAdES_BASELINE_B:
			return null;
		case XAdES_BASELINE_T:
			final XAdESLevelBaselineT extensionT = new XAdESLevelBaselineT(certificateVerifier);
			extensionT.setTspSource(tspSource);
			return extensionT;
		case XAdES_C:
			final XAdESLevelC extensionC = new XAdESLevelC(certificateVerifier);
			extensionC.setTspSource(tspSource);
			return extensionC;
		case XAdES_X:
			final XAdESLevelX extensionX = new XAdESLevelX(certificateVerifier);
			extensionX.setTspSource(tspSource);
			return extensionX;
		case XAdES_XL:
			final XAdESLevelXL extensionXL = new XAdESLevelXL(certificateVerifier);
			extensionXL.setTspSource(tspSource);
			return extensionXL;
		case XAdES_A:
			final XAdESLevelA extensionA = new XAdESLevelA(certificateVerifier);
			extensionA.setTspSource(tspSource);
			return extensionA;
		case XAdES_BASELINE_LT:
			final XAdESLevelBaselineLT extensionLT = new XAdESLevelBaselineLT(certificateVerifier);
			extensionLT.setTspSource(tspSource);
			return extensionLT;
		case XAdES_BASELINE_LTA:
			final XAdESLevelBaselineLTA extensionLTA = new XAdESLevelBaselineLTA(certificateVerifier);
			extensionLTA.setTspSource(tspSource);
			return extensionLTA;
		default:
			throw new DSSException("Unsupported signature format " + parameters.getSignatureLevel());
		}
	}
	
	/**
	 * Only DETACHED and ENVELOPING signatures are allowed
	 * 
	 * @param parameters
	 */
	private void assertMultiDocumentsAllowed(XAdESSignatureParameters parameters) {
		SignaturePackaging signaturePackaging = parameters.getSignaturePackaging();
		if (signaturePackaging == null || SignaturePackaging.ENVELOPED == signaturePackaging) {
			throw new DSSException("Not supported operation (only DETACHED or ENVELOPING are allowed)");
		}
	}
	
	public FileSystemKeyStoreKeyingDataProvider createFileSystemKeyingDataProvider(
            String keyStoreType,
            String keyStorePath,
            String keyStorePwd,
            boolean returnFullChain) throws KeyStoreException
    {
        keyStorePath = toPlatformSpecificFilePath(keyStorePath);
        return new FileSystemKeyStoreKeyingDataProvider(keyStoreType, keyStorePath,
                new FirstCertificateSelector(),
                new DirectPasswordProvider(keyStorePwd),
                new DirectPasswordProvider(keyStorePwd), returnFullChain);
    }
	
	 public static String toPlatformSpecificFilePath(String path)
    {
        return path.replace('/', File.separatorChar);
    }

//    public static String toPlatformSpecificXMLDirFilePath(String fileName)
//    {
//        return toPlatformSpecificFilePath("./src/test/xml/" + fileName);
//    }
//
//    public static String toPlatformSpecificCertDirFilePath(String fileName)
//    {
//        return toPlatformSpecificFilePath("./src/test/cert/" + fileName);
//	}
	 
	


}
