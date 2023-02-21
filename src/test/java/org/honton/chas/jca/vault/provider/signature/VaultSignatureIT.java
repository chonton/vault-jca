package org.honton.chas.jca.vault.provider.signature;

import com.github.tomakehurst.wiremock.client.VerificationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.Date;
import org.honton.chas.jca.vault.provider.VaultPrivateKey;
import org.honton.chas.jca.vault.provider.VaultProvider;
import org.honton.chas.jca.vault.provider.VaultPublicKey;
import org.honton.chas.jca.vault.provider.keygen.VaultParameterSpec;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaParameterSpec;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaKeyType;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaParameterSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class VaultSignatureIT {

  private static final byte[] MESSAGE =
      "I am your father's brother's nephew's cousin's former roommate."
          .getBytes(StandardCharsets.US_ASCII);

  private static final String NAME = VaultProvider.register().getName();

  private final KeyStore keyStore;

  VaultSignatureIT() throws GeneralSecurityException, IOException {
    keyStore = KeyStore.getInstance(NAME, NAME);
    keyStore.load(null, null);
  }

  private static VaultParameterSpec getParams(SignatureAlgorithm signatureAlgorithm) {
    VaultParameterSpec keyAlg = signatureAlgorithm.getVaultKeyAlgorithm();
    if (keyAlg instanceof VaultRsaKeyType) {
      return new VaultRsaParameterSpec(signatureAlgorithm.name(), (VaultRsaKeyType) keyAlg);
    }
    return new VaultEcdsaParameterSpec(signatureAlgorithm.name(), (VaultEcdsaKeyAlgorithm) keyAlg);
  }

  private static void verify(Signature signature, PublicKey publicKey, byte[] signatureBytes)
      throws GeneralSecurityException {
    signature.initVerify(publicKey);
    signature.update(MESSAGE);
    Assertions.assertTrue(signature.verify(signatureBytes));
  }

  @Order(10)
  @ParameterizedTest
  @EnumSource(SignatureAlgorithm.class)
  void signatureAlgorithm(SignatureAlgorithm signAlgorithm) throws GeneralSecurityException {
    KeyPairGenerator keyGen =
        KeyPairGenerator.getInstance(signAlgorithm.getJcaKeyAlgorithm(), NAME);
    AlgorithmParameterSpec params = getParams(signAlgorithm);
    keyGen.initialize(params);

    KeyPair keyPair = keyGen.generateKeyPair();
    String jcaSignatureAlgorithm = signAlgorithm.getJcaSignatureAlgorithm();
    Signature signature = Signature.getInstance(jcaSignatureAlgorithm, NAME);
    signature.initSign(keyPair.getPrivate());
    signature.update(MESSAGE);
    byte[] signatureBytes = signature.sign();

    verify(signature, keyPair.getPublic(), signatureBytes);

    Assertions.assertTrue(keyStore.containsAlias(signAlgorithm.name()));
    PrivateKey privateKey = (PrivateKey) keyStore.getKey(signAlgorithm.name(), null);
    Assertions.assertEquals(keyPair.getPublic(), privateKey);

    Certificate certificate = keyStore.getCertificate(signAlgorithm.name());
    PublicKey publicKey = certificate.getPublicKey();
    Assertions.assertEquals(keyPair.getPublic(), publicKey);

    AlgorithmParameterSpec jcaParameterSpec = signAlgorithm.getJcaParameterSpec();
    if (jcaParameterSpec != null) {
      signature = Signature.getInstance("RSASSA-PSS");
      signature.setParameter(jcaParameterSpec);
    } else {
      signature = Signature.getInstance(jcaSignatureAlgorithm);
    }
    Assertions.assertNotEquals("Vault", signature.getProvider().getName());
    verify(signature, publicKey, signatureBytes);
  }

  @Order(20)
  @Test
  void listKeys() throws GeneralSecurityException {
    for (String alias : Collections.list(keyStore.aliases())) {
      Assertions.assertTrue(keyStore.getKey(alias, null) instanceof VaultPrivateKey);
      Assertions.assertTrue(keyStore.getCertificate(alias).getPublicKey() instanceof VaultPublicKey);
      Date date = keyStore.getCreationDate(alias);
      Assertions.assertTrue(date.getTime() < System.currentTimeMillis());
      long diff = System.currentTimeMillis() - date.getTime();
      Assertions.assertTrue(diff < 10_000);
    }
  }

  @Order(5)
  @Test
  void nonExistent() throws GeneralSecurityException {
    Assertions.assertFalse(keyStore.containsAlias("Dave"));
    Assertions.assertNull(keyStore.getKey("Dave", "'s not here, man".toCharArray()));
    Assertions.assertNull(keyStore.getCreationDate("Dave"));
    Assertions.assertEquals(0, keyStore.size());
  }

  void format() throws Exception {

    String keyName = "";
    String keyAlgorithmName = "";
    String signatureAlgorithmName = "";

    // initialize KeyStore
    KeyStore keyStore = KeyStore.getInstance(NAME, NAME);
    keyStore.load(null, null);

    // get an existing Vault public key
    PublicKey publicKey = (PublicKey) keyStore.getKey(keyName, null);

    // list keys
    Collections.list(keyStore.aliases());

    // keyAlgorithmName is from KeyPairGenerator Algorithms table below
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithmName, NAME);

    VaultParameterSpec keySpec;
    if ("EC".equals(keyAlgorithmName)) {
      keySpec = new VaultRsaParameterSpec(keyName, VaultRsaKeyType.RSA_3072);
    } else {
      keySpec = new VaultEcdsaParameterSpec(keyName, VaultEcdsaKeyAlgorithm.ECDSA_P521);
    }

    keyPairGenerator.initialize(keySpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    publicKey = keyPair.getPublic();
    PrivateKey privateKey = keyPair.getPrivate();

    // algorithm is from Signature Algorithms table below
    Signature signature = Signature.getInstance(signatureAlgorithmName, NAME);

    // sign
    signature.initSign(keyPair.getPrivate());
    signature.update(MESSAGE);
    byte[] signatureBytes = signature.sign();

    // verify
    signature.initVerify(publicKey);
    signature.update(MESSAGE);
    if (!signature.verify(signatureBytes)) {
      throw new VerificationException("");
    }
  }
}
