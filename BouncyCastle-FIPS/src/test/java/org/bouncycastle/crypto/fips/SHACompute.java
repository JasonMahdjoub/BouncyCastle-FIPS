package org.bouncycastle.crypto.fips;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.SHA256Digest;
import org.bouncycastle.crypto.internal.macs.HMac;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class SHACompute {
	private static byte[] calculateModuleHMAC(JarFile jarFile)
    {
        // this code is largely the standard approach to self verifying a JCE with some minor modifications. It will calculate
        // the SHA-256 HMAC on the classes.
        try
        {
            HMac hMac = new HMac(new SHA256Digest());

            hMac.init(new KeyParameterImpl(Strings.toByteArray(CryptoServicesRegistrar.MODULE_HMAC_KEY)));

            // build an index to make sure we get things in the same order.
            Map<String, JarEntry> index = new TreeMap<String, JarEntry>();

            for (Enumeration<JarEntry> entries = jarFile.entries(); entries.hasMoreElements();)
            {
                JarEntry jarEntry = entries.nextElement();

                // Skip directories and META-INF.
                if (jarEntry.isDirectory() || jarEntry.getName().startsWith("META-INF/"))
                {
                    continue;
                }

                Object last = index.put(jarEntry.getName(), jarEntry);
                if (last != null)
                {
                    IllegalStateException e =  new IllegalStateException("Unable to initialize module: duplicate entry found in jar file");
                    throw e;
                }
            }

            byte[] buf = new byte[8192];
            for (String name : index.keySet())
            {
                JarEntry jarEntry = index.get(name);
                InputStream is = jarFile.getInputStream(jarEntry);

                // Read in each jar entry. A SecurityException will
                // be thrown if a signature/digest check fails - if that happens
                // we'll just return an empty checksum

                // header information
                byte[] encName = Strings.toUTF8ByteArray(jarEntry.getName());
                hMac.update((byte)0x5B);   // '['
                hMac.update(encName, 0, encName.length);
                hMac.update(Pack.longToBigEndian(jarEntry.getSize()), 0, 8);
                hMac.update((byte)0x5D);    // ']'

                // contents
                int n;
                while ((n = is.read(buf, 0, buf.length)) != -1)
                {
                    hMac.update(buf, 0, n);
                }
                is.close();
            }

            hMac.update((byte)0x5B);   // '['
            byte[] encName = Strings.toUTF8ByteArray("END");
            hMac.update(encName, 0, encName.length);
            hMac.update((byte)0x5D);    // ']'

            byte[] hmacResult = new byte[hMac.getMacSize()];

            hMac.doFinal(hmacResult, 0);

            return hmacResult;
        }
        catch (Exception e)
        {
            return new byte[32];
        }
    }
	
	public static void main(String args[]) throws IOException
	{
		System.out.println(new String(Hex.encode(calculateModuleHMAC(new JarFile(new File("build/libs/BouncyCastle-FIPS-1.0.4.jar").getCanonicalFile())))));
	}
}
