package org.honton.chas.jca.vault.provider.signature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import org.honton.chas.jca.vault.provider.VaultApiFactory;
import org.honton.chas.jca.vault.provider.VaultProvider;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.VaultParameterSpec;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaParameterSpec;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class VaultSignatureIT {

  private static final byte[] MESSAGE =
      "I am your father's brother's nephew's cousin's former roommate."
          .getBytes(StandardCharsets.US_ASCII);

  private final VaultProvider vaultProvider;
  private final KeyStore keyStore;

  VaultSignatureIT() throws GeneralSecurityException, IOException {
    vaultProvider = VaultApiFactory.getVaultProvider();
    keyStore = KeyStore.getInstance("Vault", vaultProvider);
    keyStore.load(null, null);
  }

  private static VaultParameterSpec<?> getParams(SignatureAlgorithm signatureAlgorithm) {
    VaultKeyAlgorithm keyAlg = signatureAlgorithm.getVaultKeyAlgorithm();
    if (keyAlg instanceof VaultRsaKeyAlgorithm) {
      return new VaultRsaParameterSpec(signatureAlgorithm.name(), (VaultRsaKeyAlgorithm) keyAlg);
    }
    return new VaultEcdsaParameterSpec(signatureAlgorithm.name(), (VaultEcdsaKeyAlgorithm) keyAlg);
  }

  private static void verify(Signature signature, PublicKey publicKey, byte[] signatureBytes)
      throws GeneralSecurityException {
    signature.initVerify(publicKey);
    signature.update(MESSAGE);
    Assertions.assertTrue(signature.verify(signatureBytes));
  }

  @ParameterizedTest
  @EnumSource(SignatureAlgorithm.class)
  @Timeout(30)
  void signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) throws GeneralSecurityException {
    KeyPairGenerator keyGen =
        KeyPairGenerator.getInstance(signatureAlgorithm.getJcaKeyAlgorithm(), vaultProvider);
    AlgorithmParameterSpec params = getParams(signatureAlgorithm);
    keyGen.initialize(params);

    KeyPair keyPair = keyGen.generateKeyPair();
    Signature signature =
        Signature.getInstance(signatureAlgorithm.getJcaSignatureAlgorithm(), vaultProvider);
    signature.initSign(keyPair.getPrivate());
    signature.update(MESSAGE);
    byte[] signatureBytes = signature.sign();

    verify(signature, keyPair.getPublic(), signatureBytes);

    PublicKey publicKey = (PublicKey) keyStore.getKey(signatureAlgorithm.name(), null);
    verify(signature, publicKey, signatureBytes);
  }
}
