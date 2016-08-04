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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.inject.Inject;
import javax.inject.Named;
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
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            Path ksPath = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
            keyStore.load(Files.newInputStream(ksPath), "changeit".toCharArray());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (InputStream caInput = new BufferedInputStream(
                // this files is shipped with the application
                getClass().getResourceAsStream("DSTRootCAX3.der"))) {
                Certificate crt = cf.generateCertificate(caInput);
                this.logger.info("Added Cert for [{}]", ((X509Certificate) crt).getSubjectDN());

                keyStore.setCertificateEntry("DSTRootCAX3", crt);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            SSLContext.setDefault(sslContext);
        } catch (Exception e) {
            throw new InitializationException("Failed to regsiter Let's Encryp certificate", e);
        }
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // Implemented in #initialize() so that it's done as soon as possible
    }
}
