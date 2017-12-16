package eu.europa.esig.dss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.security.cert.X509CertSelector;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.transforms.Transforms;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

//import eu.europa.ec.markt.dss.countersignature.xades.old.CanonicalizationEnum;
//import eu.europa.ec.markt.dss.countersignature.xades.old.NombreNodo;
//import eu.europa.ec.markt.dss.countersignature.xades.old.URIEncoder;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.NamespaceContextMap;
import eu.europa.esig.dss.ResourceLoader;
import eu.europa.esig.dss.XAdESNamespaces;

public class DssUtilsService{
	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DssUtilsService.class);
	
	static final String OID_2_5_4_5 = "OID.2.5.4.5";
	static final String ID = "Id";
	static final String ID_MAYUS = "ID";
	static final String ID_MINUS = "id";
	
	public static final String ID_ATTRIBUTE_NAME = "id";
	public static final String XAD_ESV141_XSD = "/XAdESv141.xsd";
	
	
	private static int[] XML_ENTITIES = { 34, 38, 39, 60, 62 };
	
	public static final String MD2_RSA = "MD2withRSA";
	public static final String MD5_RSA = "MD5withRSA";
    public static final String SHA1_RSA = "SHA1withRSA";
	public static final String SHA1_DSA = "SHA1withDSA";
	public static final String SHA256_RSA = "SHA256withRSA";
	public static final String SHA384_RSA = "SHA384withRSA";
	public static final String SHA512_RSA = "SHA512withRSA";
	
	public static final String MD2 = "MD2";
	public static final String MD5 = "MD5";
	public static final String SHA1 = "SHA-1";
	public static final String SHA256 = "SHA-256";
    public static final String SHA512 = "SHA-512";
	public static final String SHA384 = "SHA-384";
	private static Map<String, String> mapOIDs = new HashMap();
	private static Map<String, String> mapReverseOIDs = new HashMap();
	private static Map<String, Integer> mapBytesLengths = new HashMap();
	private static Map<String, String> mapURIXMLSignatures = new HashMap();
	private static Map<String, String> mapReverseURIXMLSignatures = new HashMap();
//	private static HashMap mapOIDs = new HashMap();
//	private static HashMap mapReverseOIDs = new HashMap();

	private static DocumentBuilderFactory dbFactory;
	private static final XPathFactory factory = XPathFactory.newInstance();
	private static NamespaceContextMap namespacePrefixMapper;
	private static final Map<String, String> namespaces;
	private static final Set<String> transforms;
	private static final Set<String> canonicalizers;
	
   private final static String[] IDs = {ID, ID_MINUS, ID_MAYUS}; 
	
	private static Random rnd = new Random(new Date().getTime());
	private final static int RND_MAX_SIZE = 1048576;
	
	/** Sentencia de selección de nodo por xpointer. */
	public static final String XPOINTER_ID  = "#xpointer(id('";
	/** Sentencia de selección del nodo raíz por xpointer. */
    public static final String XPOINTER_ROOT = "#xpointer(/)";
    
    private static ArrayList<String> NODOS_DE_X = null;
    
    /*  59 */   //private static final II18nManager I18N = I18nFactory.getI18nManager("MITyCLibXAdES");
    /*     */   private static final String POLICY_DNIE_AUTHENTICATE = "2.16.724.1.2.2.2.4";
    /*     */   private static final String POLICY_DNIE_SIGN = "2.16.724.1.2.2.2.3";
    /*  67 */   private static final X509CertSelector CS_DNIE_AUTHENTICATE = new X509CertSelector();
    /*     */ 
    /*  69 */   private static final X509CertSelector CS_DNIE_SIGN = new X509CertSelector();
    /*     */   public static final String DIGEST_ALG_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    /*     */   public static final String DIGEST_ALG_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#sha256";
    /*     */   public static final String DIGEST_ALG_SHA256_enc = "http://www.w3.org/2001/04/xmlenc#sha256";
    /*     */   public static final String DIGEST_ALG_SHA256_hmac = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
    /*     */   public static final String DIGEST_ALG_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#sha512";
    /*     */   public static final String DIGEST_ALG_SHA512_enc = "http://www.w3.org/2001/04/xmlenc#sha512";
    /*     */   public static final String DIGEST_ALG_SHA512_hmac = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
    /*     */   public static final String DIGEST_ALG_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#sha224";
    /*     */   public static final String DIGEST_ALG_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    /*     */   public static final String DIGEST_ALG_MD2 = "http://www.w3.org/2001/04/xmldsig-more#md2";
    /*     */   public static final String DIGEST_ALG_MD4 = "http://www.w3.org/2001/04/xmldsig-more#md4";
    /*     */   public static final String DIGEST_ALG_MD5 = "http://www.w3.org/2001/04/xmldsig-more#md5";
    /*     */   public static final String DIGEST_ALG_RIPEMD128 = "http://www.w3.org/2001/04/xmldsig-more#ripemd128";
    /*     */   public static final String DIGEST_ALG_RIPEMD160 = "http://www.w3.org/2001/04/xmldsig-more#ripemd160";
    /*     */   public static final String DIGEST_ALG_RIPEMD256 = "http://www.w3.org/2001/04/xmldsig-more#ripemd256";
    /*     */   public static final String DIGEST_ALG_RIPEMD320 = "http://www.w3.org/2001/04/xmldsig-more#ripemd320";
    /*     */   public static final String DIGEST_ALG_TIGER = "http://www.w3.org/2001/04/xmldsig-more#tiger";
    /*     */   public static final String DIGEST_ALG_WHIRLPOOL = "http://www.w3.org/2001/04/xmldsig-more#whirlpool";
    /*     */   public static final String DIGEST_ALG_GOST3411 = "http://www.w3.org/2001/04/xmldsig-more#gost3411";

	static {

		Init.init();

		namespacePrefixMapper = new NamespaceContextMap();
		namespaces = new HashMap<String, String>();
		registerDefaultNamespaces();

		transforms = new HashSet<String>();
		registerDefaultTransforms();

		canonicalizers = new HashSet<String>();
		registerDefaultCanonicalizers();
		
		  mapOIDs.put("MD2withRSA", "1.2.840.113549.1.1.2");
	      mapOIDs.put("MD5withRSA", "1.2.840.113549.1.1.4");
	      mapOIDs.put("SHA1withRSA", "1.2.840.113549.1.1.5");
	      mapOIDs.put("SHA1withDSA", "1.2.840.10040.4.3");
	      mapOIDs.put("SHA256withRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption.getId());
	      mapOIDs.put("SHA384withRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption.getId());
	      mapOIDs.put("SHA512withRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption.getId());
	      
	        mapOIDs.put("MD2", "1.3.14.7.2.2.1");
	        mapOIDs.put("MD5", "1.2.840.113549.2.5");
	        mapOIDs.put("SHA-1", "1.3.14.3.2.26");
	        mapOIDs.put("SHA-256", "2.16.840.1.101.3.4.2.1");
	        mapOIDs.put("SHA-384", "2.16.840.1.101.3.4.2.2");
	        mapOIDs.put("SHA-512", "2.16.840.1.101.3.4.2.3");
	        
	        
	       mapReverseOIDs.put("1.2.840.113549.1.1.2", "MD2withRSA");
	       mapReverseOIDs.put("1.2.840.113549.1.1.4", "MD5withRSA");
	       mapReverseOIDs.put("1.2.840.113549.1.1.5", "SHA1withRSA");
	       mapReverseOIDs.put("1.2.840.10040.4.3", "SHA1withDSA");
	       mapReverseOIDs.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256withRSA");
	       mapReverseOIDs.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384withRSA");
	       mapReverseOIDs.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512withRSA");
	    
	             
	        mapReverseOIDs.put("1.3.14.7.2.2.1", "MD2");
	        mapReverseOIDs.put("1.2.840.113549.2.5", "MD5");
	        mapReverseOIDs.put("1.3.14.3.2.26", "SHA-1");
	        mapReverseOIDs.put("2.16.840.1.101.3.4.2.1", "SHA-256");
	        mapReverseOIDs.put("2.16.840.1.101.3.4.2.2", "SHA-384");
	        mapReverseOIDs.put("2.16.840.1.101.3.4.2.3", "SHA-512");
	             
	        mapBytesLengths.put("MD2", Integer.valueOf(16));
	        mapBytesLengths.put("MD5", Integer.valueOf(16));
	        mapBytesLengths.put("SHA-1", Integer.valueOf(20));
	        mapBytesLengths.put("SHA-256", Integer.valueOf(32));
	        mapBytesLengths.put("SHA-384", Integer.valueOf(48));
	        mapBytesLengths.put("SHA-512", Integer.valueOf(64));
	             
	        mapURIXMLSignatures.put("MD2", "http://www.w3.org/2001/04/xmldsig-more#md2");
	        mapURIXMLSignatures.put("MD5", "http://www.w3.org/2001/04/xmldsig-more#md5");
	        mapURIXMLSignatures.put("SHA-1", "http://www.w3.org/2000/09/xmldsig#sha1");
	        mapURIXMLSignatures.put("SHA-256", "http://www.w3.org/2001/04/xmldsig-more#sha256");
	        mapURIXMLSignatures.put("SHA-384", "http://www.w3.org/2001/04/xmldsig-more#sha384");
	        mapURIXMLSignatures.put("SHA-512", "http://www.w3.org/2001/04/xmldsig-more#sha512");
	             
	        mapReverseURIXMLSignatures.put("http://www.w3.org/2001/04/xmldsig-more#md2", "MD2");
	        mapReverseURIXMLSignatures.put("http://www.w3.org/2001/04/xmldsig-more#md5", "MD5");
	        mapReverseURIXMLSignatures.put("http://www.w3.org/2000/09/xmldsig#sha1", "SHA-1");
	        mapReverseURIXMLSignatures.put("http://www.w3.org/2001/04/xmldsig-more#sha256", "SHA-256");
	        mapReverseURIXMLSignatures.put("http://www.w3.org/2001/04/xmldsig-more#sha384", "SHA-384");
	        mapReverseURIXMLSignatures.put("http://www.w3.org/2001/04/xmldsig-more#sha512", "SHA-512");
	
    		/*     */     try
    		/*     */     {
    		/*  72 */       CS_DNIE_AUTHENTICATE.setPolicy(new HashSet(Arrays.asList(new String[] { "2.16.724.1.2.2.2.4" })));
    		/*  73 */       CS_DNIE_SIGN.setPolicy(new HashSet(Arrays.asList(new String[] { "2.16.724.1.2.2.2.3" })));
    		/*     */     } catch (IOException ex) {
    		/*  75 */       logger.warn("i18n.mityc.xades.utils.2");
    		/*  76 */       if (logger.isDebugEnabled())
    		/*  77 */         logger.debug(ex.getMessage(), ex);
    		/*     */     }
    		/*  48 */     NODOS_DE_X = new ArrayList(6);
    		/*  49 */     NODOS_DE_X.add("SignatureValue");
    		/*  50 */     NODOS_DE_X.add("SignatureTimeStamp");
    		/*  51 */     NODOS_DE_X.add("CompleteCertificateRefs");
    		/*  52 */     NODOS_DE_X.add("CompleteRevocationRefs");
    		/*  53 */     NODOS_DE_X.add("AttributeCertificateRefs");
    		/*  54 */     NODOS_DE_X.add("AttributeRevocationRefs");
	}

	private static Schema schema = null;

	/**
	 * This method registers the default namespaces.
	 */
	private static void registerDefaultNamespaces() {

		registerNamespace("ds", XMLSignature.XMLNS);
		registerNamespace("dsig", XMLSignature.XMLNS);
		registerNamespace("xades", XAdESNamespaces.XAdES); // 1.3.2
		registerNamespace("xades141", XAdESNamespaces.XAdES141);
		registerNamespace("xades122", XAdESNamespaces.XAdES122);
		registerNamespace("xades111", XAdESNamespaces.XAdES111);
		//registerNamespace("asic", ASiCNamespaces.ASiC);
	}

	/**
	 * This method registers the default transforms.
	 */
	private static void registerDefaultTransforms() {

		registerTransform(Transforms.TRANSFORM_BASE64_DECODE);
		registerTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		registerTransform(Transforms.TRANSFORM_XPATH);
		registerTransform(Transforms.TRANSFORM_XPATH2FILTER);
		registerTransform(Transforms.TRANSFORM_XPOINTER);
		registerTransform(Transforms.TRANSFORM_XSLT);
	}

	/**
	 * This method registers the default canonicalizers.
	 */
	private static void registerDefaultCanonicalizers() {

		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_PHYSICAL);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS);
	}

	/**
	 * This class is an utility class and cannot be instantiated.
	 */
	private DssUtilsService() {
	}

	/**
	 * This method allows to register a namespace and associated prefix. If the prefix exists already it is replaced.
	 *
	 * @param prefix    namespace prefix
	 * @param namespace namespace
	 * @return true if this map did not already contain the specified element
	 */
	public static boolean registerNamespace(final String prefix, final String namespace) {

		final String put = namespaces.put(prefix, namespace);
		namespacePrefixMapper.registerNamespace(prefix, namespace);
		return put == null;
	}

	/**
	 * This method allows to register a transformation.
	 *
	 * @param transformURI the URI of transform
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerTransform(final String transformURI) {

		final boolean added = transforms.add(transformURI);
		return added;
	}

	/**
	 * This method allows to register a canonicalizer.
	 *
	 * @param c14nAlgorithmURI the URI of canonicalization algorithm
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerCanonicalizer(final String c14nAlgorithmURI) {

		final boolean added = canonicalizers.add(c14nAlgorithmURI);
		return added;
	}

	/**
	 * @param xpathString XPath query string
	 * @return
	 */
	private static XPathExpression createXPathExpression(final String xpathString) {

      /* XPath */
		final XPath xpath = factory.newXPath();
		xpath.setNamespaceContext(namespacePrefixMapper);
		try {
			final XPathExpression expr = xpath.compile(xpathString);
			return expr;
		} catch (XPathExpressionException ex) {
			throw new DSSException(ex);
		}
	}

	/**
	 * Return the Element corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return
	 */
	public static Element getElement(final Node xmlNode, final String xPathString) {

		return (Element) getNode(xmlNode, xPathString);
	}

	/**
	 * Return the Node corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return
	 */
	public static Node getNode(final Node xmlNode, final String xPathString) {

		final NodeList list = getNodeList(xmlNode, xPathString);
		if (list.getLength() > 1) {
			throw new DSSException("More than one result for XPath: " + xPathString);
		}
		return list.item(0);
	}

	/**
	 * This method returns the list of children's names for a given {@code Node}.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return {@code List} of children's names
	 */
	public static List<String> getChildrenNames(final Node xmlNode, final String xPathString) {

		ArrayList<String> childrenNames = new ArrayList<String>();

		final Element element = getElement(xmlNode, xPathString);
		if (element != null) {

			final NodeList unsignedProperties = element.getChildNodes();
			for (int ii = 0; ii < unsignedProperties.getLength(); ++ii) {

				final Node node = unsignedProperties.item(ii);
				childrenNames.add(node.getLocalName());
			}
		}
		return childrenNames;
	}

	/**
	 * Returns the NodeList corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return
	 * @throws XPathExpressionException
	 */
	public static NodeList getNodeList(final Node xmlNode, final String xPathString) {

		try {

			final XPathExpression expr = createXPathExpression(xPathString);
			final NodeList evaluated = (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
			return evaluated;
		} catch (XPathExpressionException e) {

			throw new DSSException(e);
		}
	}

	/**
	 * Returns the String value of the corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return string value of the XPath query
	 * @throws XPathExpressionException
	 */
	public static String getValue(final Node xmlNode, final String xPathString) {

		try {

			final XPathExpression xPathExpression = createXPathExpression(xPathString);
			final String string = (String) xPathExpression.evaluate(xmlNode, XPathConstants.STRING);
			return string.trim();
		} catch (XPathExpressionException e) {

			throw new DSSException(e);
		}
	}

	/**
	 * Returns the number of found elements based on the XPath query.
	 *
	 * @param xmlNode
	 * @param xPathString
	 * @return
	 */
	public static int count(final Node xmlNode, final String xPathString) {

		try {

			final XPathExpression xPathExpression = createXPathExpression(xPathString);
			final Double number = (Double) xPathExpression.evaluate(xmlNode, XPathConstants.NUMBER);
			return number.intValue();
		} catch (XPathExpressionException e) {

			throw new DSSException(e);
		}
	}

	/**
	 * Document Object Model (DOM) Level 3 Load and Save Specification See: http://www.w3.org/TR/2004/REC-DOM-Level-3-LS-20040407/
	 *
	 * @param xmlNode The node to be serialized.
	 * @return
	 */
	public static byte[] serializeNode(final Node xmlNode) {

		try {

			final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
			final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
			final LSSerializer writer = impl.createLSSerializer();

			final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			final LSOutput output = impl.createLSOutput();
			output.setByteStream(buffer);
			writer.write(xmlNode, output);

			final byte[] bytes = buffer.toByteArray();
			return bytes;
		} catch (ClassNotFoundException e) {
			throw new DSSException(e);
		} catch (InstantiationException e) {
			throw new DSSException(e);
		} catch (IllegalAccessException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by the fact that the attribute does not have attached type of
	 * information. Another solution is to parse the XML against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
	 * This method is useful to carry out tests with different signature provider.
	 *
	 * @param context
	 * @param element
	 */
	public static void recursiveIdBrowse(final DOMValidateContext context, final Element element) {

		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {

			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				final Element childElement = (Element) node;
				setIDIdentifier(context, childElement);
				recursiveIdBrowse(context, childElement);
			}
		}
	}

	/**
	 * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by the fact that the attribute does not have attached type of
	 * information. Another solution is to parse the XML against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
	 *
	 * @param element
	 */
	public static void recursiveIdBrowse(final Element element) {

		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {

			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				final Element childElement = (Element) node;
				setIDIdentifier(childElement);
				recursiveIdBrowse(childElement);
			}
		}
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then it is returned. If there is more than one ID attributes then the first one is returned.
	 *
	 * @param element to be checked
	 * @return the ID attribute value or null
	 */
	public static String getIDIdentifier(final Element element) {

		final NamedNodeMap attributes = element.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getNodeName();
			if (localName != null) {
				final String id = localName.toLowerCase();
				if (ID_ATTRIBUTE_NAME.equals(id)) {

					return item.getTextContent();
				}
			}
		}
		return null;
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID attribute.
	 *
	 * @param childElement
	 */
	public static void setIDIdentifier(final DOMValidateContext context, final Element childElement) {

		final NamedNodeMap attributes = childElement.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getNodeName();
			if (localName != null) {
				final String id = localName.toLowerCase();
				if (ID_ATTRIBUTE_NAME.equals(id)) {

					context.setIdAttributeNS(childElement, null, localName);
					break;
				}
			}
		}
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID attribute.
	 *
	 * @param childElement
	 */
	public static void setIDIdentifier(final Element childElement) {

		final NamedNodeMap attributes = childElement.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getNodeName();
			if (localName != null) {
				final String id = localName.toLowerCase();
				if (ID_ATTRIBUTE_NAME.equals(id)) {

					childElement.setIdAttribute(localName, true);
					break;
				}
			}
		}
	}

	/**
	 * Guarantees that the xmlString builder has been created.
	 *
	 * @throws ParserConfigurationException
	 */
	private static void ensureDocumentBuilder() throws DSSException {

		if (dbFactory != null) {
			return;
		}
		dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
	}

	/**
	 * Creates the new empty Document.
	 *
	 * @return
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 */
	public static Document buildDOM() {

		ensureDocumentBuilder();

		try {
			return dbFactory.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML string.
	 *
	 * @param xmlString The string representing the dssDocument to be created.
	 * @return
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 */
	public static Document buildDOM(final String xmlString) throws DSSException {

		final InputStream input = new ByteArrayInputStream(DSSUtils.getUtf8Bytes(xmlString));
		return buildDOM(input);
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on byte array.
	 *
	 * @param bytes The bytes array representing the dssDocument to be created.
	 * @return
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 */
	public static Document buildDOM(final byte[] bytes) throws DSSException {

		final InputStream input = new ByteArrayInputStream(bytes);
		return buildDOM(input);
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML inputStream.
	 *
	 * @param inputStream The inputStream stream representing the dssDocument to be created.
	 * @return
	 * @throws SAXException
	 * @throws IOException
	 */
	public static Document buildDOM(final InputStream inputStream) throws DSSException {

		try {
			ensureDocumentBuilder();

			final Document rootElement = dbFactory.newDocumentBuilder().parse(inputStream);
			return rootElement;
		} catch (SAXParseException e) {
			throw new DSSException(e);
		} catch (SAXException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the {@link eu.europa.ec.markt.dss.signature.DSSDocument}.
	 *
	 * @param dssDocument The DSS representation of the document from which the dssDocument is created.
	 * @return
	 * @throws DSSException
	 */
	public static Document buildDOM(final DSSDocument dssDocument) throws DSSException {

		final InputStream input = dssDocument.openStream();
		try {

			final Document doc = buildDOM(input);
			return doc;
		} finally {
			IOUtils.closeQuietly(input);
		}
	}

	/**
	 * This method writes formatted {@link org.w3c.dom.Node} to the outputStream.
	 *
	 * @param node
	 * @param out
	 */
	public static void printDocument(final Node node, final OutputStream out) {
		printDocument(node, out, false);
	}

	/**
	 * This method writes formatted {@link org.w3c.dom.Node} to the outputStream.
	 *
	 * @param node
	 * @param out
	 */
	private static void printDocument(final Node node, final OutputStream out, final boolean raw) {

		try {

			final TransformerFactory tf = TransformerFactory.newInstance();
			final Transformer transformer = tf.newTransformer();
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			if (!raw) {

				transformer.setOutputProperty(OutputKeys.INDENT, "yes");
				transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "3");
			}
			transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

			final DOMSource xmlSource = new DOMSource(node);
			final OutputStreamWriter writer = new OutputStreamWriter(out, "UTF-8");
			final StreamResult outputTarget = new StreamResult(writer);
			transformer.transform(xmlSource, outputTarget);
		} catch (Exception e) {

			// Ignore
		}
	}

	/**
	 * This method writes raw {@link org.w3c.dom.Node} (without blanks) to the outputStream.
	 *
	 * @param node
	 * @param out
	 */
	public static void printRawDocument(final Node node, final OutputStream out) {

		trimWhitespace(node);
		printDocument(node, out, true);
	}

	/**
	 * This method trims all whitespaces in TEXT_NODE.
	 *
	 * @param node
	 */
	public static void trimWhitespace(final Node node) {

		final NodeList children = node.getChildNodes();
		for (int ii = 0; ii < children.getLength(); ++ii) {

			final Node child = children.item(ii);
			if (child.getNodeType() == Node.TEXT_NODE) {

				final String textContent = child.getTextContent();
				child.setTextContent(textContent.trim());
			}
			trimWhitespace(child);
		}
	}

	/**
	 * This method writes formatted {@link org.w3c.dom.Node} to the outputStream.
	 *
	 * @param dssDocument
	 * @param out
	 * @throws IOException 
	 * @throws DSSException 
	 */
	public static void printDocument(final DSSDocument dssDocument, final OutputStream out) throws DSSException, IOException {

		final byte[] bytes = IOUtils.toByteArray(dssDocument.openStream());
		final Document document = buildDOM(bytes);
		printDocument(document, out, false);
	}

	/**
	 * This method says if the framework can canonicalize an XML data with the provided method.
	 *
	 * @param canonicalizationMethod the canonicalization method to be checked
	 * @return true if it is possible to canonicalize false otherwise
	 */
	public static boolean canCanonicalize(final String canonicalizationMethod) {

		if (transforms.contains(canonicalizationMethod)) {
			return false;
		}
		final boolean contains = canonicalizers.contains(canonicalizationMethod);
		return contains;
	}

	/**
	 * This method canonicalizes the given array of bytes using the {@code canonicalizationMethod} parameter.
	 *
	 * @param canonicalizationMethod canonicalization method
	 * @param toCanonicalizeBytes    array of bytes to canonicalize
	 * @return array of canonicalized bytes
	 * @throws DSSException if any error is encountered
	 */
	public static byte[] canonicalize(final String canonicalizationMethod, final byte[] toCanonicalizeBytes) throws DSSException {

		try {

			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			return c14n.canonicalize(toCanonicalizeBytes);
		} catch (InvalidCanonicalizerException e) {
			throw new DSSException(e);
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		} catch (SAXException e) {
			throw new DSSException(e);
		} catch (CanonicalizationException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method canonicalizes the given {@code Node}.
	 *
	 * @param canonicalizationMethod canonicalization method
	 * @param node                   {@code Node} to canonicalize
	 * @return array of canonicalized bytes
	 */
	public static byte[] canonicalizeSubtree(final String canonicalizationMethod, final Node node) {

		try {

			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			final byte[] canonicalized = c14n.canonicalizeSubtree(node);
			return canonicalized;
		} catch (InvalidCanonicalizerException e) {
			throw new DSSException(e);
		} catch (CanonicalizationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method canonicalizes the given {@code NodeList}.
	 *
	 * @param canonicalizationMethod canonicalization method
	 * @param nodeList               {@code NodeList} to canonicalize
	 * @return array of canonicalized bytes
	 */
	public static byte[] canonicalizeXPathNodeSet(final String canonicalizationMethod, final Set<Node> nodeList) {

		try {

			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			final byte[] canonicalized = c14n.canonicalizeXPathNodeSet(nodeList);
			return canonicalized;
		} catch (InvalidCanonicalizerException e) {
			throw new DSSException(e);
		} catch (CanonicalizationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method creates and adds a new XML {@code Element} with text value
	 *
	 * @param document  root document
	 * @param parentDom parent node
	 * @param namespace namespace
	 * @param name      element name
	 * @param value     element text node value
	 * @return added element
	 */
	public static Element addTextElement(final Document document, final Element parentDom, final String namespace, final String name, final String value) {

		final Element dom = document.createElementNS(namespace, name);
		parentDom.appendChild(dom);
		final Text valueNode = document.createTextNode(value);
		dom.appendChild(valueNode);
		return dom;
	}

	/**
	 * This method creates and adds a new XML {@code Element}
	 *
	 * @param document  root document
	 * @param parentDom parent node
	 * @param namespace namespace
	 * @param name      element name
	 * @return added element
	 */
	public static Element addElement(final Document document, final Element parentDom, final String namespace, final String name) {

		final Element dom = document.createElementNS(namespace, name);
		parentDom.appendChild(dom);
		return dom;
	}

	public static byte[] transformDomToByteArray(final Document documentDom) {

		try {

			final TransformerFactory transformerFactory = TransformerFactory.newInstance();
			final Transformer transformer = transformerFactory.newTransformer();
			final String xmlEncoding = documentDom.getXmlEncoding();
			if (!xmlEncoding.isEmpty()) {
				transformer.setOutputProperty(OutputKeys.ENCODING, xmlEncoding);
			}
			final DOMSource source = new DOMSource(documentDom);

			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			final StreamResult streamResult = new StreamResult(byteArrayOutputStream);
			transformer.transform(source, streamResult);
			byte[] byteArray = byteArrayOutputStream.toByteArray();
			return byteArray;
		} catch (final TransformerException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method sets a text node to the given DOM element.
	 *
	 * @param document  root document
	 * @param parentDom parent node
	 * @param text      text to be added
	 */
	public static void setTextNode(final Document document, final Element parentDom, final String text) {

		final Text textNode = document.createTextNode(text);
		parentDom.appendChild(textNode);
	}

	/**
	 * Creates a DOM Document object of the specified type with its document element.
	 *
	 * @param namespaceURI  the namespace URI of the document element to create or null
	 * @param qualifiedName the qualified name of the document element to be created or null
	 * @param element       document {@code Element}
	 * @return {@code Document}
	 */
	public static Document createDocument(final String namespaceURI, final String qualifiedName, final Element element) {

		DOMImplementation domImpl;
		try {
			domImpl = dbFactory.newDocumentBuilder().getDOMImplementation();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
		final Document newDocument = domImpl.createDocument(namespaceURI, qualifiedName, null);
		final Element newElement = newDocument.getDocumentElement();
		newDocument.adoptNode(element);
		newElement.appendChild(element);

		return newDocument;
	}

	/**
	 * Creates a DOM document without document element.
	 *
	 * @param namespaceURI  the namespace URI of the document element to create or null
	 * @param qualifiedName the qualified name of the document element to be created or null
	 * @return {@code Document}
	 */
	public static Document createDocument(final String namespaceURI, final String qualifiedName) {

		DOMImplementation domImpl;
		try {
			domImpl = dbFactory.newDocumentBuilder().getDOMImplementation();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}

		return domImpl.createDocument(namespaceURI, qualifiedName, null);
	}


	/**
	 * Creates a DOM Document object of the specified type with its document elements.
	 *
	 * @param namespaceURI
	 * @param qualifiedName
	 * @param element1
	 * @param element2
	 * @return {@code Document}
	 */
	public static Document createDocument(final String namespaceURI, final String qualifiedName, final Element element1, final Element element2) {

		DOMImplementation domImpl;
		try {
			domImpl = dbFactory.newDocumentBuilder().getDOMImplementation();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
		final Document newDocument = domImpl.createDocument(namespaceURI, qualifiedName, null);
		final Element newElement = newDocument.getDocumentElement();
		newDocument.adoptNode(element1);
		newElement.appendChild(element1);

		newDocument.adoptNode(element2);
		newElement.appendChild(element2);

		return newDocument;
	}

	/**
	 * Converts a given {@code Date} to a new {@code XMLGregorianCalendar}.
	 *
	 * @param date the date to be converted
	 * @return the new {@code XMLGregorianCalendar} or null
	 */
	public static XMLGregorianCalendar createXMLGregorianCalendar(final Date date) {

		if (date == null) {
			return null;
		}
		final GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		try {

			XMLGregorianCalendar xmlGregorianCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
			xmlGregorianCalendar.setFractionalSecond(null);
			xmlGregorianCalendar = xmlGregorianCalendar.normalize(); // to UTC = Zulu
			return xmlGregorianCalendar;
		} catch (DatatypeConfigurationException e) {
			// LOG.warn("Unable to properly convert a Date to an XMLGregorianCalendar",e);
		}
		return null;
	}

	/**
	 * This method allows to convert the given text (XML representation of a date) to the {@code Date}.
	 *
	 * @param text the text representing the XML date
	 * @return {@code Date} converted or null
	 */
	public static Date getDate(final String text) {

		try {

			final DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
			final XMLGregorianCalendar xmlGregorianCalendar = datatypeFactory.newXMLGregorianCalendar(text);
			return xmlGregorianCalendar.toGregorianCalendar().getTime();
		} catch (DatatypeConfigurationException e) {
			// do nothing
		}
		return null;
	}

	/**
	 * This method retrieves an element based on its ID
	 *
	 * @param currentDom the DOM in which the element has to be retrieved
	 * @param elementId  the specified ID
	 * @param namespace  the namespace to take into account
	 * @param tagName    the tagName of the element to find
	 * @return the
	 * @throws DSSNullException
	 */
	public static Element getElementById(Document currentDom, String elementId, String namespace, String tagName) throws DSSException {

		Element element = null;
		NodeList nodes = currentDom.getElementsByTagNameNS(namespace, tagName);

		for (int i = 0; i < nodes.getLength(); i++) {
			element = (Element) nodes.item(i);
			if (elementId.equals(getIDIdentifier(element))) {
				return element;
			}
		}
		if (element == null) {
			throw new DSSException("Not eg element by Id");
		}
		return null;
	}

	/**
	 * This method enables a user to add a specific namespace + corresponding prefix
	 *
	 * @param namespace a {@code HashMap} containing the additional namespace, with the prefix as key and the namespace URI as value
	 * @deprecated From 4.3.0-RC use eu.europa.ec.markt.dss.DSSXMLUtils#registerNamespace(java.lang.String, java.lang.String)
	 */
	public static void addNamespace(HashMap<String, String> namespace) {

		namespaces.putAll(namespace);
		for (final Map.Entry<String, String> entry : namespace.entrySet()) {

			namespacePrefixMapper.registerNamespace(entry.getKey(), entry.getValue());
		}
	}

	/**
	 * This method allows to validate an XML against the XAdES XSD schema.
	 *
	 * @param streamSource {@code InputStream} XML to validate
	 * @return empty {@code String} if the XSD validates the XML, error message otherwise
	 */
	public static String validateAgainstXSD(final StreamSource streamSource) {

		try {

			if (schema == null) {
				schema = getSchema();
			}
			final Validator validator = schema.newValidator();
			validator.validate(streamSource);
			return "";
		} catch (Exception e) {
			logger.warn("Error during the XML schema validation!", e);
			return e.getMessage();
		}
	}

	private static Schema getSchema() throws SAXException {

		final ResourceLoader resourceLoader = new ResourceLoader();
		final InputStream xadesXsd = resourceLoader.getResource(XAD_ESV141_XSD);
		final SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		return factory.newSchema(new StreamSource(xadesXsd));
	}

	/**
	 * This method allows to convert an XML {@code Node} to a {@code String}.
	 *
	 * @param node {@code Node} to be converted
	 * @return {@code String} representation of the node
	 */
	public static String xmlToString(final Node node) {

		try {

			final Source source = new DOMSource(node);
			final StringWriter stringWriter = new StringWriter();
			final Result result = new StreamResult(stringWriter);
			final TransformerFactory factory = TransformerFactory.newInstance();
			final Transformer transformer = factory.newTransformer();
			transformer.transform(source, result);
			return stringWriter.getBuffer().toString();
		} catch (TransformerConfigurationException e) {
			throw new DSSException(e);
		} catch (TransformerException e) {
			throw new DSSException(e);
		}
	}
	


}
