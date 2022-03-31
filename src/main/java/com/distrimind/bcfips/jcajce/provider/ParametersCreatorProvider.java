package com.distrimind.bcfips.jcajce.provider;

import com.distrimind.bcfips.crypto.Parameters;

interface ParametersCreatorProvider<T extends Parameters>
{
    ParametersCreator get(T parameters);
}
