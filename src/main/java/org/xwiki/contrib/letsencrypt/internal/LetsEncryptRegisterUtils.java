package org.xwiki.contrib.letsencrypt.internal;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Let's Encrypt related utility class.
 * 
 * @version $Id$
 * @since 1.1
 */
public final class LetsEncryptRegisterUtils
{
    private static final Logger LOGGER = LoggerFactory.getLogger(LetsEncryptRegisterUtils.class);

    private static final String CERTIFICATE_ALIAS = "DSTRootCAX3";

    private static final String CERTIFICATE_FILE = CERTIFICATE_ALIAS + ".der";

    /**
     * Utility class.
     */
    private LetsEncryptRegisterUtils()
    {

    }

    /**
     * Register Let's Encrypt certificate in the current JVM.
     */
    public static void register()
    {
        try {
            String keyStore = System.getProperty("javax.net.ssl.keyStore");

            SSLContext sslContext;
            if (keyStore != null) {
                sslContext = updateCustomTrustStore(keyStore);
            } else {
                sslContext = updateOracleTrustStore();
            }

            if (sslContext != null) {
                SSLContext.setDefault(sslContext);
            }
        } catch (Exception e) {
            // No need to crash the whole XWiki initialization for it
            LOGGER.warn("Failed to regsiter Let's Encryp certificate", e);
        }
    }

    private static Certificate getCertificate() throws CertificateException, IOException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        try (InputStream caInput = new BufferedInputStream(
            // this files is shipped with the application
            LetsEncryptRegisterUtils.class.getResourceAsStream(CERTIFICATE_FILE))) {
            return cf.generateCertificate(caInput);
        }
    }

    private static SSLContext getSSLContext() throws NoSuchAlgorithmException
    {
        return SSLContext.getInstance("TLS");
    }

    private static SSLContext updateOracleTrustStore()
        throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, KeyManagementException
    {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        Path ksPath = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        keyStore.load(Files.newInputStream(ksPath), "changeit".toCharArray());

        // Make sure the certificate is not already registered
        if (keyStore.getCertificate(CERTIFICATE_ALIAS) == null) {
            // Add Let's Encrypt certificate
            Certificate certificate = getCertificate();
            LOGGER.info("Added certificate [{}] in default [{}]", ((X509Certificate) certificate).getSubjectDN(),
                ksPath);
            keyStore.setCertificateEntry(CERTIFICATE_ALIAS, certificate);

            TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            SSLContext sslContext = getSSLContext();
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            return sslContext;
        }

        return null;
    }

    private static SSLContext updateCustomTrustStore(String keyStoreString) throws KeyStoreException,
        NoSuchAlgorithmException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException
    {
        String keyStoreTypeString = System.getProperty("javax.net.ssl.keyStoreType", KeyStore.getDefaultType());
        String keyStorePasswordString = System.getProperty("javax.net.ssl.keyStorePassword", "");

        KeyManager[] kms = null;
        if (keyStoreString != null && !keyStoreString.equals("NONE")) {
            KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keyStore = KeyStore.getInstance(keyStoreTypeString);

            try (FileInputStream fs = new FileInputStream(keyStoreString)) {
                keyStore.load(fs, keyStorePasswordString.toCharArray());
            }

            // Make sure the certificate is not already registered
            if (keyStore.getCertificate(CERTIFICATE_ALIAS) != null) {
                // Add Let's Encrypt certificate
                Certificate certificate = getCertificate();
                LOGGER.info("Added certificate [{}] in custom [{}]", ((X509Certificate) certificate).getSubjectDN(),
                    keyStoreString);
                keyStore.setCertificateEntry(CERTIFICATE_ALIAS, certificate);

                char[] password;
                if (keyStorePasswordString.length() > 0) {
                    password = keyStorePasswordString.toCharArray();
                } else {
                    password = null;
                }
                keyManagerFactory.init(keyStore, password);
                kms = keyManagerFactory.getKeyManagers();

                SSLContext sslContext = getSSLContext();
                sslContext.init(kms, null, null);

                return sslContext;
            }
        }

        return null;
    }
}
