package org.honton.chas.jca.vault.provider.signature;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.rsa.VaultRsaKeyAlgorithm;

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
    shaSize = getShaSize(name);
    keyAlgorithm = keyAlgorithm(name);
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

  // https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#messagedigest-algorithms
  public String getJcaDigestAlgorithm() {
    return "SHA-" + shaSize;
  }

  public String getVaultHashAlgorithm() {
    return "sha2-" + shaSize;
  }

  public VaultKeyAlgorithm getVaultKeyAlgorithm() {
    return keyAlgorithm.vaultKeyAlgorithm(shaSize);
  }

  public String getVaultSignatureAlgorithm() {
    return keyAlgorithm.getVaultSignatureAlgorithm();
  }

  @RequiredArgsConstructor
  @Getter
  enum KeyAlgorithm {
    RSASSA_PSS("RSASSA-PSS", "pss") {
      @Override
      String jcaSignatureAlgorithm(String shaSize) {
        return "RSASSA-PSS/SHA" + shaSize;
      }

    },
    RSASSA_PKCS("RSA", "pkcs1v15") {
      @Override
      String jcaSignatureAlgorithm(String shaSize) {
        return "SHA" + shaSize + "withRSA";
      }

    },
    ECDSA("EC", null) {
      @Override
      String jcaSignatureAlgorithm(String shaSize) {
        return "SHA" + shaSize + "withECDSA";
      }

      @Override
      VaultKeyAlgorithm vaultKeyAlgorithm(String shaSize) {
        switch (shaSize) {
          case "256":
            return VaultEcdsaKeyAlgorithm.ECDSA_P256;
          case "384":
            return VaultEcdsaKeyAlgorithm.ECDSA_P384;
          default:
            return VaultEcdsaKeyAlgorithm.ECDSA_P521;
        }
      }
    };

    private final String jcaKeyAlgorithm;
    private final String vaultSignatureAlgorithm;

    abstract String jcaSignatureAlgorithm(String shaSize);

    VaultKeyAlgorithm vaultKeyAlgorithm(String shaSize) {
      switch (shaSize) {
        case "2048":
          return VaultRsaKeyAlgorithm.RSA_2048;
        case "3072":
          return VaultRsaKeyAlgorithm.RSA_3072;
        default:
          return VaultRsaKeyAlgorithm.RSA_4096;
      }
    }
  }
}
