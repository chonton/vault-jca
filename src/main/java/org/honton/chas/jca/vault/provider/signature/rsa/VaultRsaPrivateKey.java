package org.honton.chas.jca.vault.provider.signature.rsa;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import org.honton.chas.jca.vault.provider.VaultPrivateKey;

public class VaultRsaPrivateKey extends VaultPrivateKey implements RSAPrivateKey {

    public VaultRsaPrivateKey(String name, int version) {
        super(name, version);
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public BigInteger getModulus() {
        return noExport();
    }

    @Override
    public BigInteger getPrivateExponent() {
        return noExport();
    }
}
