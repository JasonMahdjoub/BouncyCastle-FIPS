/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package com.distrimind.bcfips.asn1.misc;

import com.distrimind.bcfips.asn1.DERIA5String;

public class VerisignCzagExtension
    extends DERIA5String
{
    public VerisignCzagExtension(
        DERIA5String str)
    {
        super(str.getString());
    }

    public String toString()
    {
        return "VerisignCzagExtension: " + this.getString();
    }
}
