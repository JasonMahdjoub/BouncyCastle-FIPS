/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.misc;

import com.distrimind.bcfips.asn1.DERIA5String;

public class NetscapeRevocationURL
    extends DERIA5String
{
    public NetscapeRevocationURL(
        DERIA5String str)
    {
        super(str.getString());
    }

    public String toString()
    {
        return "NetscapeRevocationURL: " + this.getString();
    }
}
