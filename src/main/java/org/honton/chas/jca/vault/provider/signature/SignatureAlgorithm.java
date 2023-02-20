package org.honton.chas.jca.vault.provider.signature;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.honton.chas.jca.vault.provider.keygen.VaultParameterSpec;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaKeyType;

public enum SignatureAlgorithm {
  RSASSA_PSS_SHA_256,
  RSASSA_PSS_SHA_384,
  RSASSA_PSS_SHA_512,

  RSASSA_PKCS_SHA_256,
  RSASSA_PKCS_SHA_384,
  RSASSA_PKCS_SHA_512,

  ECDSA_SHA_256,
  ECDSA_SHA_384,
  ECDSA_SHA_512;

  private final KeyAlgorithm keyAlgorithm;
  private final String shaSize;

  SignatureAlgorithm() {
    String name = name();
    keyAlgorithm = keyAlgorithm(name);
    shaSize = getShaSize(name);
  }

  private static KeyAlgorithm keyAlgorithm(String name) {
    if (name.startsWith("RSASSA_PSS_")) {
      return KeyAlgorithm.RSASSA_PSS;
    }
    if (name.startsWith("RSASSA_PKCS_")) {
      return KeyAlgorithm.RSASSA_PKCS;
    }
    return KeyAlgorithm.ECDSA;
  }

  private static String getShaSize(String name) {
    return name.substring(name.indexOf("SHA_") + 4);
  }

  // https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keypairgenerator-algorithms
  public String getJcaKeyAlgorithm() {
    return keyAlgorithm.getJcaKeyAlgorithm();
  }

  // https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms
  public String getJcaSignatureAlgorithm() {
    return keyAlgorithm.jcaSignatureAlgorithm(shaSize);
  }

  public AlgorithmParameterSpec getJcaParameterSpec() {
    return keyAlgorithm.jcaParameterSpec("SHA-" + shaSize);
  }

  public String getVaultHashAlgorithm() {
    return "sha2-" + shaSize;
  }

  public VaultParameterSpec getVaultKeyAlgorithm() {
    return keyAlgorithm.vaultKeyAlgorithm(shaSize);
  }

  public String getVaultSignatureAlgorithm() {
    return keyAlgorithm.getVaultSignatureAlgorithm();
  }

  @RequiredArgsConstructor
  @Getter
  enum KeyAlgorithm {
    RSASSA_PKCS("RSA", "pkcs1v15"),
    RSASSA_PSS("RSASSA-PSS", "pss") {
      @Override
      String jcaSignatureAlgorithm(String shaSize) {
        return super.jcaSignatureAlgorithm(shaSize) + "andMGF1";
      }
      @Override
      PSSParameterSpec jcaParameterSpec(String mdName) {
        switch (mdName) {
          case "SHA-256":
            return new PSSParameterSpec(mdName, "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
          case "SHA-384":
            return new PSSParameterSpec(mdName, "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
          case "SHA-512":
            return new PSSParameterSpec(mdName, "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
          default:
            throw new UnsupportedOperationException(mdName);
        }
      }
    },
    ECDSA("EC", null) {
      @Override
      String jcaSignatureAlgorithm(String shaSize) {
        return "SHA" + shaSize + "withECDSA";
      }

      @Override
      VaultParameterSpec vaultKeyAlgorithm(String shaSize) {
        switch (shaSize) {
          case "256":
            return VaultEcdsaKeyAlgorithm.ECDSA_P256;
          case "384":
            return VaultEcdsaKeyAlgorithm.ECDSA_P384;
          case "512":
            return VaultEcdsaKeyAlgorithm.ECDSA_P521;
          default:
            throw new UnsupportedOperationException(shaSize);
        }
      }
    };

    private final String jcaKeyAlgorithm;
    private final String vaultSignatureAlgorithm;

    String jcaSignatureAlgorithm(String shaSize) {
      return "SHA" + shaSize + "withRSA";
    }

    AlgorithmParameterSpec jcaParameterSpec(String mdName) {
      return null;
    }

    VaultParameterSpec vaultKeyAlgorithm(String shaSize) {
      switch (shaSize) {
        case "256":
          return VaultRsaKeyType.RSA_2048;
        case "384":
          return VaultRsaKeyType.RSA_3072;
        case "512":
          return VaultRsaKeyType.RSA_4096;
        default:
          throw new UnsupportedOperationException(shaSize);
      }
    }
  }
}
