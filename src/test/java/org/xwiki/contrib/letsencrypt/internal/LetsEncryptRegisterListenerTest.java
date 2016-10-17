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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.test.mockito.MockitoComponentMockingRule;

/**
 * Validate {@link LetsEncryptRegisterListener}.
 * 
 * @version $Id$
 */
public class LetsEncryptRegisterListenerTest
{
    @Rule
    public MockitoComponentMockingRule<LetsEncryptRegisterListener> mocker =
        new MockitoComponentMockingRule<>(LetsEncryptRegisterListener.class);

    @Before
    public void before() throws ComponentLookupException
    {
        // Register letsencrypt
        this.mocker.getComponentUnderTest();
    }
    
    @Test
    public void test() throws MalformedURLException, IOException
    {
        new URL("https://helloworld.letsencrypt.org").openConnection().connect();
    }
}
