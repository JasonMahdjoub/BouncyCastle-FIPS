package com.distrimind.bcfips.crypto.util;

import java.io.IOException;

import com.distrimind.bcfips.asn1.ASN1OctetString;
import com.distrimind.bcfips.asn1.ASN1Primitive;
import com.distrimind.bcfips.asn1.DEROctetString;
import com.distrimind.bcfips.util.Arrays;

class DerUtil
{
    static ASN1OctetString getOctetString(byte[] data)
    {
        if (data == null)
        {
            return new DEROctetString(new byte[0]);
        }

        return new DEROctetString(Arrays.clone(data));
    }

    static byte[] toByteArray(ASN1Primitive primitive)
    {
        try
        {
            return primitive.getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Cannot get encoding: " + e.getMessage(), e);
        }
    }
}
