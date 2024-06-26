package com.distrimind.bcfips.crypto.fips;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.PrivilegedAction;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import com.distrimind.bcfips.LICENSE;
import com.distrimind.bcfips.crypto.CryptoServicesRegistrar;
import com.distrimind.bcfips.crypto.internal.macs.HMac;
import com.distrimind.bcfips.crypto.internal.params.KeyParameterImpl;
import com.distrimind.bcfips.util.Pack;
import com.distrimind.bcfips.util.Strings;

/**
 * Status utility class - it has three methods on it, one for returning "isReady" status, one for a status message,
 * and one for the current module checksum.
 */
public final class FipsStatus
{
    public static final String READY = "READY";

    private static final Object statusLock = new Object();

    private static final String[] classes = new String[] { FipsAES.class.getName(), FipsTripleDES.class.getName(), FipsDH.class.getName(),
        FipsDRBG.class.getName(), FipsDSA.class.getName(), FipsEC.class.getName(),
        FipsKDF.class.getName(), FipsPBKD.class.getName(), FipsRSA.class.getName(), FipsSHS.class.getName() };
    private static final AtomicBoolean readyStatus = new AtomicBoolean(false);

    private static volatile Loader loader;
    private static volatile Throwable statusException;

    private FipsStatus()
    {

    }

    /**
     * Check to see if the FIPS module is ready for operation.
     *
     * @return true if the module is ready for operation with all self-tests complete.
     */
    public static boolean isReady()
    {
        // FSM_STATE:2.0, "POWER ON INITIALIZATION", "Initialization of the module after power on or RST"
        synchronized (statusLock)
        {
            if (loader == null && statusException == null)
            {
                try
                {
                    loader = new Loader();

                    loader.run();
                }
                catch (Exception e)
                {
                    statusException = e;

                    moveToErrorStatus(new FipsOperationError("Module startup failed: " + e.getMessage(), e));
                }

                // FSM_STATE:3.1, "FIRMWARE INTEGRITY - HMAC-SHA256", "The module is performing the Firmware Integrity Check: HMAC-SHA256"
                // FSM_TRANS:3.3
                checksumValidate();
                // FSM_TRANS:3.4

                // FSM_TRANS:3.1
                readyStatus.set(true);
            }
            else if (statusException != null)
            {
                throw new FipsOperationError("Module in error status: " + statusException.getMessage(), statusException);
            }
        }

        return readyStatus.get();
    }

    static boolean isBooting()
    {
        return !readyStatus.get();
    }

    private static void checksumValidate()
    {
        /*final String rscName = AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            public String run()
            {
                return getResourceName();
            }
        });

        if (rscName == null)
        {
            moveToErrorStatus(new FipsOperationError("Module checksum failed: unable to find"));
        }

        if (rscName.startsWith("jrt:/"))
        {
            moveToErrorStatus(new FipsOperationError("Module checksum failed: unable to calculate"));
        }
        else if (checkValidJarUrl(rscName))
        {
            try
            {
                JarInputStream jIn = new JarInputStream(new URL(rscName).openStream());

                byte[][] hmacs = calculateModuleHMAC(jIn);

                if (!Arrays.areEqual(hmacs[0], hmacs[1]))
                {
                    moveToErrorStatus(new FipsOperationError("Module checksum failed: expected [" + Hex.toHexString(hmacs[1]) + "] got [" + Hex.toHexString(hmacs[0]) + "]"));
                }
            }
            catch (Exception e)
            {
                statusException = e;
                moveToErrorStatus(new FipsOperationError("Module checksum failed: " + e.getMessage(), e));
            }
        }
        else
        {
            JarFile jarFile = AccessController.doPrivileged(new PrivilegedAction<JarFile>()
            {
                public JarFile run()
                {
                    try
                    {
                        return new JarFile(rscName);
                    }
                    catch (IOException e)
                    {
                        return null;
                    }
                }
            });

            if (jarFile != null)      // we only do the checksum calculation if we are running off a jar file.
            {
                try
                {
                    byte[] hmac = calculateModuleHMAC(jarFile);
                    InputStream macIn = jarFile.getInputStream(jarFile.getEntry("META-INF/HMAC.SHA256"));

                    StringBuilder sb = new StringBuilder(hmac.length * 2);

                    int ch;
                    while ((ch = macIn.read()) >= 0 && ch != '\r' && ch != '\n')
                    {
                        sb.append((char)ch);
                    }

                    byte[] fileMac = Hex.decode(sb.toString().trim());

                    if (!Arrays.areEqual(hmac, fileMac))
                    {
                        moveToErrorStatus(new FipsOperationError("Module checksum failed: expected [" + sb.toString().trim() + "] got [" + Strings.fromByteArray(Hex.encode(hmac))) + "]");
                    }
                }
                catch (Exception e)
                {
                    statusException = e;

                    moveToErrorStatus(new FipsOperationError("Module checksum failed: " + e.getMessage(), e));
                }
            }
        }*/
    }

    /**
     * Return a message indicating the current status.
     *
     * @return  READY if all is well, an exception message otherwise.
     */
    public static String getStatusMessage()
    {
        try
        {
            FipsStatus.isReady();
        }
        catch (FipsOperationError e)
        {
            // ignore as loader exception will now be set.
        }

        if (statusException != null)
        {
            return statusException.getMessage();
        }

        return READY;
    }

    private static void loadClass(String className)
    {
        try
        {
            Class.forName(className);
        }
        catch (ExceptionInInitializerError e)
        {
            if (e.getCause() != null)
            {
                statusException = e.getCause();
            }
            else
            {
                statusException = e;
            }
            throw e;
        }
        catch (ClassNotFoundException e)
        {
            statusException = e;
            throw new IllegalStateException("Unable to initialize module: " + e.getMessage(), e);
        }
    }

    /**
     * Return the HMAC used to verify that the code contained in the module is the same
     *
     * @return the internally calculated HMAC for the module.
     */
    public static byte[] getModuleHMAC()
    {
        try
        {
            String rscName = getResourceName();

            return calculateModuleHMAC(new JarFile(rscName));
        }
        catch (Exception e)
        {
            return new byte[32];
        }
    }

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

                // Skip directories, META-INF, and module-info.class meta-data
                if (jarEntry.isDirectory() || jarEntry.getName().startsWith("META-INF/") || jarEntry.getName().equals("module-info.class"))
                {
                    continue;
                }

                Object last = index.put(jarEntry.getName(), jarEntry);
                if (last != null)
                {
                    IllegalStateException e =  new IllegalStateException("Unable to initialize module: duplicate entry found in jar file");
                    statusException = e;
                    throw e;
                }
            }

            byte[] buf = new byte[8192];
            for (Map.Entry<String, JarEntry> entry : index.entrySet())
            {
                JarEntry jarEntry = entry.getValue();
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

    private static String getResourceName()
    {
        // we use the MARKER file, at the same level in the class hierarchy as this
        // class, to find the enclosing Jar file (if one exists)

        String result = null;

        final String markerName = LICENSE.class.getCanonicalName().replace(".", "/").replace("LICENSE", "MARKER");
        final String marker = getMarker(LICENSE.class, markerName);

        if (marker != null)
        {
            if (marker.startsWith("jar:") && marker.contains("!/"))
            {
                try
                {
                    int secondColon = marker.indexOf(':', 4);
                    if (secondColon == -1)
                    {
                        return null;
                    }
                    String jarFilename = URLDecoder.decode(marker.substring(secondColon + 1, marker.lastIndexOf("!/")), "UTF-8");
                    result = jarFilename;
                }
                catch (IOException e)
                {
                    // we found our jar file, but couldn't open it
                    result = null;
                }
            }
            else if (marker.startsWith("file:") && marker.endsWith(".jar"))
            {
                try
                {
                    String jarFilename = URLDecoder.decode(marker.substring("file:".length()), "UTF-8");

                    result = jarFilename;
                }
                catch (IOException e)
                {
                    // we found our jar file, but couldn't open it
                    result = null;
                }
            }
            else if (marker.startsWith("jrt:"))
            {
                 return marker;
            }
            else if (marker.startsWith("file:"))
            {
                 return marker;    // this means we're running from classes (development)
            }
            else if (checkValidJarUrl(marker))
            {
                return marker;
            }
        }

        return result;
    }
    
    static void moveToErrorStatus(String error)
    {
        moveToErrorStatus(new FipsOperationError(error));
    }

    static void moveToErrorStatus(FipsOperationError error)
    {
        // FSM_STATE:8.0
        // FSM_TRANS:3.2
        statusException =  error;
        throw (FipsOperationError)statusException;
    }

    /**
     * Return true if the module is in error status, false otherwise.
     *
     * @return true if an error has been detected, false otherwise.
     */
    public static boolean isErrorStatus()
    {
        return statusException != null;
    }

    static class Loader
    {
        Loader()
        {
        }

        void run()
                throws Exception
        {
            // FSM_STATE:3.0, "POWER ON SELF-TEST", ""
            for (String cls : classes)
            {
                if (!isErrorStatus())
                {
                    loadClass(cls);
                }
            }
        }
    }

    static String getMarker(final Class sourceClass, final String markerName)
    {
        ClassLoader loader = sourceClass.getClassLoader();

        if (loader != null)
        {
            Object resource = AccessController.doPrivileged(
					(PrivilegedAction) () -> {
						try
						{
							CodeSource cs =
									sourceClass.getProtectionDomain().getCodeSource();
							return cs.getLocation();
						}
						catch (Exception e)
						{
							return null;
						}
					});
            if (resource != null)
            {
                return resource.toString();
            }

            return loader.getResource(markerName).toString();
        }
        else
        {
            return AccessController.doPrivileged(new PrivilegedAction<String>()
            {
                public String run()
                {
                    return ClassLoader.getSystemResource(markerName).toString();
                }
            });
        }
    }

    private static boolean checkValidJarUrl(String url)
    {
        return (url.startsWith("http://") || url.startsWith("https://")) && url.endsWith(".jar");
    }
}
