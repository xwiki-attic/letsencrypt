/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
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

import javax.inject.Inject;
import javax.inject.Named;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

/**
 * Automatically register Let's Encrypt certificate at init.
 * 
 * @version $Id$
 * @since 1.0
 */
@Component
@Named(LetsEncryptRegisterListener.NAME)
public class LetsEncryptRegisterListener extends AbstractEventListener implements Initializable
{
    /**
     * The name of teh listener.
     */
    public static final String NAME = "letsencrypt";

    private static final String CERTIFICATE_ALIAS = "DSTRootCAX3";

    private static final String CERTIFICATE_FILE = CERTIFICATE_ALIAS + ".der";

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public LetsEncryptRegisterListener()
    {
        super(NAME);
    }

    @Override
    public void initialize() throws InitializationException
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
            throw new InitializationException("Failed to regsiter Let's Encryp certificate", e);
        }
    }

    private Certificate getCertificate() throws CertificateException, IOException
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        try (InputStream caInput = new BufferedInputStream(
            // this files is shipped with the application
            getClass().getResourceAsStream(CERTIFICATE_FILE))) {
            return cf.generateCertificate(caInput);
        }
    }

    private SSLContext getSSLContext() throws NoSuchAlgorithmException
    {
        return SSLContext.getInstance("TLS");
    }

    private SSLContext updateOracleTrustStore()
        throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, KeyManagementException
    {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        Path ksPath = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        keyStore.load(Files.newInputStream(ksPath), "changeit".toCharArray());

        // Make sure the certificate is not already registered
        if (keyStore.getCertificate(CERTIFICATE_ALIAS) == null) {
            // Add Let's Encrypt certificate
            Certificate certificate = getCertificate();
            this.logger.info("Added certificate [{}] in default [{}]", ((X509Certificate) certificate).getSubjectDN(),
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

    private SSLContext updateCustomTrustStore(String keyStoreString) throws KeyStoreException, NoSuchAlgorithmException,
        CertificateException, IOException, KeyManagementException, UnrecoverableKeyException
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
                this.logger.info("Added certificate [{}] in custom [{}]",
                    ((X509Certificate) certificate).getSubjectDN(), keyStoreString);
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

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // Implemented in #initialize() so that it's done as soon as possible
    }
}
