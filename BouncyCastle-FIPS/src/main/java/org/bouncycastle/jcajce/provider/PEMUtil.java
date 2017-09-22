package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.PushbackInputStream;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

class PEMUtil
{
    private final String _header1;
    private final String _header2;
    private final String _footer1;
    private final String _footer2;

    PEMUtil(
        String type)
    {
        _header1 = "-----BEGIN " + type + "-----";
        _header2 = "-----BEGIN X509 " + type + "-----";
        _footer1 = "-----END " + type + "-----";
        _footer2 = "-----END X509 " + type + "-----";
    }

    private String readLine(
        PushbackInputStream in)
        throws IOException
    {
        int             c;
        StringBuffer l = new StringBuffer();

        do
        {
            while (((c = in.read()) != '\r') && c != '\n' && (c >= 0))
            {
                l.append((char)c);
            }
        }
        while (c >= 0 && l.length() == 0);

        if (c < 0)
        {
            return null;
        }

        // make sure we parse to end of line.

        while (((c = in.read()) == '\r') && c == '\n' && (c >= 0))
        {
            ;
        }

        if (c > 0)
        {
            in.unread(c);
        }

        return l.toString();
    }

    ASN1Sequence readPEMObject(
        PushbackInputStream in)
        throws IOException
    {
        String line;
        StringBuffer pemBuf = new StringBuffer();

        while ((line = readLine(in)) != null)
        {
            if (line.startsWith(_header1) || line.startsWith(_header2))
            {
                break;
            }
        }

        while ((line = readLine(in)) != null)
        {
            if (line.startsWith(_footer1) || line.startsWith(_footer2))
            {
                break;
            }

            pemBuf.append(line);
        }

        if (pemBuf.length() != 0)
        {
            try
            {
                return ASN1Sequence.getInstance(Base64.decode(pemBuf.toString()));
            }
            catch (Exception e)
            {
                throw new IOException("malformed PEM data encountered");
            }
        }

        return null;
    }
}
