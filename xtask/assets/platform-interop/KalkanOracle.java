// Independent GOST verifier for the platform-interop matrix (docs/dev/platform-interop.md).
//
// It judges signatures produced by oncl (or NCANode) with the real Kalkan JCE provider and the
// Kalkan XMLDSig configuration for Apache Santuario. The Kalkan jars are NOT part of this
// repository and are never copied into it: the harness puts the operator's copies on the
// classpath (ONCL_KALKAN_JAR, ONCL_KALKAN_XMLDSIG_JAR) and compiles this single file with the
// source launcher:
//
//   java -cp <kalkancrypt.jar>:<kalkancrypt_xmldsig.jar> KalkanOracle.java <mode> <args...>
//
// Modes (one JSON object on stdout, exit 0 when a verdict was reached):
//   raw  <alg> <cert.der> <data-file> <signature-file>
//        <alg> is ECGOST3410-2015-512, ECGOST34310 or their RAW (pre-hashed) variants
//        RAWECGOST3410-2015-512 / RAWECGOST34310; the signature is the bytes as the signer
//        wrote them, nothing is reordered here.
//   jws  <compact-jws-file> <cert.der>
//        header.payload.signature; the signing input is the ASCII of "header.payload", the
//        algorithm of the header must be ECGOST3410-2015-512.
//   wsse <soap.xml> [cert.der]
//        every ds:Signature of the message: the SignatureValue over the canonical SignedInfo
//        and the digest of every Reference are checked separately. Without cert.der the
//        certificate is the one in the signature's KeyInfo.
//
// {"ok":true|false,...} is a verdict about the signature. {"error":"..."} (exit 2) means the
// oracle itself could not run (bad arguments, missing algorithm, unreadable input): never a
// verdict, the harness turns it into a failed row.

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public final class KalkanOracle {
    private static final String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final Set<String> RAW_ALGORITHMS = Set.of(
            "ECGOST3410-2015-512",
            "RAWECGOST3410-2015-512",
            "ECGOST34310",
            "RAWECGOST34310");

    /** The oracle could not run: not a verdict. */
    private static final class OracleError extends Exception {
        OracleError(String message, Throwable cause) {
            super(message, cause);
        }

        OracleError(String message) {
            super(message);
        }
    }

    public static void main(String[] args) {
        // The Kalkan provider prints diagnostics (for instance "gost big-endian block") to
        // stdout: the answer goes to the real stdout, everything else to stderr.
        java.io.PrintStream answer = System.out;
        System.setOut(System.err);
        try {
            if (args.length == 0) {
                throw new OracleError("usage: <raw|jws|wsse> <args...>");
            }
            Security.addProvider(new kz.gov.pki.kalkan.jce.provider.KalkanProvider());
            String json = switch (args[0]) {
                case "raw" -> raw(args);
                case "jws" -> jws(args);
                case "wsse" -> wsse(args);
                default -> throw new OracleError("unknown mode " + args[0]);
            };
            answer.println(json);
        } catch (Throwable t) {
            answer.println("{\"error\":" + quote(t.getClass().getSimpleName() + ": " + t.getMessage()) + "}");
            System.exit(2);
        }
    }

    // ---- raw ---------------------------------------------------------------------------

    private static String raw(String[] args) throws Exception {
        if (args.length != 5) {
            throw new OracleError("raw <alg> <cert.der> <data-file> <signature-file>");
        }
        String algorithm = args[1];
        if (!RAW_ALGORITHMS.contains(algorithm)) {
            throw new OracleError("unsupported algorithm " + algorithm + ", one of " + RAW_ALGORITHMS);
        }
        PublicKey key = certificate(Files.readAllBytes(Path.of(args[2]))).getPublicKey();
        byte[] data = Files.readAllBytes(Path.of(args[3]));
        byte[] signature = Files.readAllBytes(Path.of(args[4]));
        boolean ok = verify(algorithm, key, data, signature);
        return "{\"ok\":" + ok + ",\"mode\":\"raw\",\"alg\":" + quote(algorithm)
                + ",\"signature_bytes\":" + signature.length + "}";
    }

    /**
     * One verification by the provider. A signature the provider refuses to parse (wrong
     * length, a value out of range) is a rejected signature; everything else that throws is
     * the oracle failing.
     */
    private static boolean verify(String algorithm, PublicKey key, byte[] data, byte[] signature)
            throws Exception {
        Signature verifier = Signature.getInstance(algorithm, "KALKAN");
        verifier.initVerify(key);
        verifier.update(data);
        try {
            return verifier.verify(signature);
        } catch (SignatureException rejected) {
            return false;
        }
    }

    // ---- jws ---------------------------------------------------------------------------

    private static String jws(String[] args) throws Exception {
        if (args.length != 3) {
            throw new OracleError("jws <compact-jws-file> <cert.der>");
        }
        String compact = Files.readString(Path.of(args[1]), StandardCharsets.US_ASCII).trim();
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 3) {
            throw new OracleError("not a compact JWS: " + parts.length + " parts");
        }
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        if (!header.matches("(?s).*\"alg\"\\s*:\\s*\"ECGOST3410-2015-512\".*")) {
            throw new OracleError("the JWS header does not name ECGOST3410-2015-512: " + header);
        }
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        PublicKey key = certificate(Files.readAllBytes(Path.of(args[2]))).getPublicKey();
        boolean ok = verify("ECGOST3410-2015-512", key, signingInput, signature);
        return "{\"ok\":" + ok + ",\"mode\":\"jws\",\"signature_bytes\":" + signature.length + "}";
    }

    // ---- wsse --------------------------------------------------------------------------

    private static String wsse(String[] args) throws Exception {
        if (args.length < 2 || args.length > 3) {
            throw new OracleError("wsse <soap.xml> [cert.der]");
        }
        X509Certificate override =
                args.length == 3 ? certificate(Files.readAllBytes(Path.of(args[2]))) : null;
        Document document = parse(Files.readAllBytes(Path.of(args[1])));
        markIds(document.getDocumentElement());
        // Kalkan's algorithm classes and URIs for Santuario (SignatureBaseGost and the GOST
        // digests of pkigovkz.xml), registered the way the vendor library does it.
        kz.gov.pki.kalkan.xmldsig.KncaXS.loadXMLSecurity();

        NodeList signatures = document.getElementsByTagNameNS(DSIG, "Signature");
        if (signatures.getLength() == 0) {
            throw new OracleError("the message has no ds:Signature");
        }
        boolean all = true;
        List<String> rendered = new ArrayList<>();
        for (int i = 0; i < signatures.getLength(); i++) {
            Element element = (Element) signatures.item(i);
            XMLSignature signature = new XMLSignature(element, "");
            X509Certificate certificate = override != null ? override : embeddedCertificate(element);
            SignedInfo info = signature.getSignedInfo();
            PublicKey key = certificate.getPublicKey();
            // Santuario's checkSignatureValue is the signature over the canonical SignedInfo AND
            // the reference digests in one boolean: the two are judged apart here (a changed
            // body leaves the first intact, a changed SignatureValue leaves the second), and the
            // combined call must agree with them.
            boolean valueOk;
            String reason = null;
            SignatureAlgorithm algorithm = info.getSignatureAlgorithm();
            algorithm.initVerify(key);
            ByteArrayOutputStream canonical = new ByteArrayOutputStream();
            info.signInOctetStream(canonical);
            algorithm.update(canonical.toByteArray());
            try {
                valueOk = algorithm.verify(signature.getSignatureValue());
            } catch (org.apache.xml.security.signature.XMLSignatureException rejected) {
                // The provider refused the SignatureValue itself (length, range).
                valueOk = false;
                reason = String.valueOf(rejected.getMessage());
            }
            boolean referencesOk = true;
            List<String> references = new ArrayList<>();
            for (int r = 0; r < info.getLength(); r++) {
                String uri = info.item(r).getURI();
                boolean digestOk;
                try {
                    digestOk = info.item(r).verify();
                } catch (org.apache.xml.security.signature.XMLSignatureException e) {
                    throw new OracleError("reference " + uri + " cannot be processed", e);
                }
                referencesOk &= digestOk;
                references.add("{\"uri\":" + quote(uri) + ",\"node\":" + quote(signedNode(document, uri))
                        + ",\"digest_ok\":" + digestOk + "}");
            }
            if (reason == null) {
                boolean combined = signature.checkSignatureValue(key);
                if (combined != (valueOk && referencesOk)) {
                    throw new OracleError("Santuario's combined check (" + combined
                            + ") disagrees with the separate checks (signature value " + valueOk
                            + ", references " + referencesOk + ")");
                }
            }
            all &= valueOk && referencesOk && info.getLength() > 0;
            rendered.add("{\"signature_value_ok\":" + valueOk
                    + (reason == null ? "" : ",\"reason\":" + quote(reason))
                    + ",\"signature_algorithm\":" + quote(info.getSignatureMethodURI())
                    + ",\"references\":[" + String.join(",", references) + "]}");
        }
        return "{\"ok\":" + all + ",\"mode\":\"wsse\",\"signatures\":[" + String.join(",", rendered) + "]}";
    }

    private static Document parse(byte[] xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    }

    /** Makes every `Id`/`ID`/`id` attribute (any namespace, e.g. wsu:Id) an ID for reference lookup. */
    private static void markIds(Element element) {
        NamedNodeMap attributes = element.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Attr attribute = (Attr) attributes.item(i);
            String name = attribute.getLocalName() != null ? attribute.getLocalName() : attribute.getName();
            if (name.equals("Id") || name.equals("ID") || name.equals("id")) {
                element.setIdAttributeNode(attribute, true);
            }
        }
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element e) {
                markIds(e);
            }
        }
    }

    private static String signedNode(Document document, String uri) {
        if (uri == null || !uri.startsWith("#")) {
            return uri == null ? "" : uri;
        }
        Element target = document.getElementById(uri.substring(1));
        return target == null ? "?" : target.getLocalName();
    }

    /** The certificate in the signature's KeyInfo: a KeyIdentifier, a BinarySecurityToken or ds:X509Certificate. */
    private static X509Certificate embeddedCertificate(Element signature) throws Exception {
        NodeList keyInfos = signature.getElementsByTagNameNS(DSIG, "KeyInfo");
        if (keyInfos.getLength() == 0) {
            throw new OracleError("the signature has no KeyInfo and no certificate was given");
        }
        Element keyInfo = (Element) keyInfos.item(0);
        String text = null;
        for (String local : new String[] {"KeyIdentifier", "BinarySecurityToken", "X509Certificate"}) {
            NodeList found = keyInfo.getElementsByTagNameNS("*", local);
            if (found.getLength() > 0) {
                text = found.item(0).getTextContent();
                break;
            }
        }
        if (text == null) {
            // A BinarySecurityToken is a sibling of the signature in wsse:Security; follow the reference.
            NodeList references = keyInfo.getElementsByTagNameNS("*", "Reference");
            if (references.getLength() > 0) {
                String uri = ((Element) references.item(0)).getAttribute("URI");
                Element token = signature.getOwnerDocument().getElementById(uri.replaceFirst("^#", ""));
                if (token != null) {
                    text = token.getTextContent();
                }
            }
        }
        if (text == null) {
            throw new OracleError("no certificate in KeyInfo (KeyIdentifier, BinarySecurityToken, X509Certificate)");
        }
        return certificate(Base64.getMimeDecoder().decode(text.trim()));
    }

    // ---- shared ------------------------------------------------------------------------

    private static X509Certificate certificate(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509", "KALKAN")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    private static String quote(String text) {
        StringWriter out = new StringWriter();
        out.write('"');
        for (char c : String.valueOf(text).toCharArray()) {
            switch (c) {
                case '"' -> out.write("\\\"");
                case '\\' -> out.write("\\\\");
                case '\n' -> out.write("\\n");
                case '\r' -> out.write("\\r");
                case '\t' -> out.write("\\t");
                default -> {
                    if (c < 0x20) {
                        out.write(String.format("\\u%04x", (int) c));
                    } else {
                        out.write(c);
                    }
                }
            }
        }
        out.write('"');
        return out.toString();
    }
}
