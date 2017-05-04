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

import javax.inject.Named;

import org.apache.commons.lang3.SystemUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.extension.version.Version;
import org.xwiki.extension.version.internal.DefaultVersion;
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

    private static final Version JAVA8_101 = new DefaultVersion("1.8.0_101");

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
        Version currentJVM = new DefaultVersion(SystemUtils.JAVA_RUNTIME_VERSION);

        // Useless in anything more recent than Java 8 101
        if (currentJVM.compareTo(JAVA8_101) < 0) {
            LetsEncryptRegisterUtils.register();
        }
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // Implemented in #initialize() so that it's done as soon as possible
    }
}
