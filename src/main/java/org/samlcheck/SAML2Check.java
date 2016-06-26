package org.samlcheck;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;

import static java.lang.System.exit;

public class SAML2Check {

    private static final Logger log = LoggerFactory.getLogger(SAML2Check.class);

    static XMLObject getSAMLResponse(File file)
            throws ConfigurationException, ParserConfigurationException,
            SAXException, IOException, UnmarshallingException {

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

        documentBuilderFactory.setNamespaceAware(true);

        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

        Document document = docBuilder.parse(new FileInputStream(file));

        Element element = document.getDocumentElement();

        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();

        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

        return unmarshaller.unmarshall(element);

    }

    public static void main(String args[]) throws URISyntaxException, MetadataProviderException, ConfigurationException, ParserConfigurationException, UnmarshallingException, SAXException, IOException, ValidationException, SecurityException {

        if (args.length < 2) {
            System.err.println("Two params are required: <saml response>.xml and <IdP metada>.xml");
            exit(-1);
        }
        File assertionFile = new File(args[0]);
        File idPFile = new File(args[1]);

        DefaultBootstrap.bootstrap();

        FilesystemMetadataProvider provider = new FilesystemMetadataProvider(idPFile);
        BasicParserPool parser = new BasicParserPool();
        parser.setNamespaceAware(true);
        provider.setParserPool(parser);
        provider.initialize();
        MetadataCredentialResolver mdCredResolver = new MetadataCredentialResolver(provider);
        KeyInfoCredentialResolver keyInfoCredResolver =
                Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
        ExplicitKeySignatureTrustEngine trustEngine = new ExplicitKeySignatureTrustEngine(mdCredResolver, keyInfoCredResolver);

        Response response = (Response) getSAMLResponse(assertionFile);

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        Signature signature = response.getAssertions().get(0).getSignature();
        profileValidator.validate(signature);


        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add( new EntityIDCriteria(response.getIssuer().getValue()) );
        criteriaSet.add( new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS) );
        criteriaSet.add( new UsageCriteria(UsageType.SIGNING) );

        try {
            trustEngine.validate(signature, criteriaSet);
        }catch (Exception ex) {
            log.error("Signature validation failed!", ex);
            exit(-1);
        }

        log.info("*** Signature validation succeeded ***");
    }
}
