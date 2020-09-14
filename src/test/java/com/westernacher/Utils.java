package com.westernacher;

import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Collection of utility methods.
 */
public class Utils {
    public static SignerInformationVerifier fromCertificate(InputStream inputStream) {
        try {
            final X509Certificate certificate = (X509Certificate) CertificateFactory
                    .getInstance("X509")
                    .generateCertificate(inputStream);
            return new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider("BC")
                    .build(certificate);
        } catch (CertificateException | OperatorCreationException e) {
            throw new RuntimeException("Failed to create a verifier from the input stream.");
        }
    }
}
