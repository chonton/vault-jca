package org.honton.chas.jca.vault.provider.signature;

import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;
import lombok.SneakyThrows;
import org.honton.chas.jca.vault.provider.VaultPrivateKey;
import org.honton.chas.jca.vault.provider.VaultPublicKey;
import org.honton.chas.vault.api.VaultApi;
import org.honton.chas.vault.api.VaultClient;

public class VaultSignature extends SignatureSpi {

  private final SignatureAlgorithm signatureAlgorithm;
  private final ByteBuffer data;

  private VaultPublicKey vaultPublicKey;
  private VaultPrivateKey vaultPrivateKey;

  @SneakyThrows
  public VaultSignature(SignatureAlgorithm signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
    data = ByteBuffer.allocate(4000);
  }

  protected VaultApi getVaultInstance() {
    return VaultClient.INSTANCE;
  }

  /**
   * Initializes this signature object with the specified public key for verification operations.
   *
   * @param publicKey the public key of the identity whose signature is going to be verified.
   */
  @Override
  protected void engineInitVerify(PublicKey publicKey) {
    vaultPublicKey = (VaultPublicKey) publicKey;
    data.clear();
  }

  /**
   * Initializes this signature object with the specified private key for signing operations.
   *
   * @param privateKey the private key of the identity whose signature will be generated.
   *     on.
   */
  @Override
  protected void engineInitSign(PrivateKey privateKey) {
    vaultPrivateKey = (VaultPrivateKey) privateKey;
    data.clear();
  }

  /**
   * Updates the data to be signed or verified using the specified byte.
   *
   * @param b the byte to use for the update.
   */
  @Override
  protected void engineUpdate(byte b) {
    data.put(b);
  }

  /**
   * Updates the data to be signed or verified, using the specified array of bytes, starting at the
   * specified offset.
   *
   * @param b the array of bytes
   * @param off the offset to start from in the array of bytes
   * @param len the number of bytes to use, starting at offset
   */
  @Override
  protected void engineUpdate(byte[] b, int off, int len) {
    data.put(b, off, len);
  }

  /**
   * Returns the signature bytes of all the data updated so far. The format of the signature depends
   * on the underlying signature scheme.
   *
   * @return the signature bytes of the signing operation's result.
   */
  @Override
  protected byte[] engineSign() {
    return getVaultInstance()
        .signData(
            vaultPrivateKey.getName(),
            vaultPrivateKey.getVersion(),
            signatureAlgorithm.getVaultSignatureAlgorithm(),
            signatureAlgorithm.getVaultHashAlgorithm(),
            data.flip());
  }

  /**
   * Verifies the passed-in signature.
   *
   * @param sigBytes the signature bytes to be verified.
   * @return true if the signature was verified, false if not.
   */
  @Override
  protected boolean engineVerify(byte[] sigBytes) {
    return getVaultInstance()
        .verifySignedData(
            vaultPublicKey.getName(),
            vaultPublicKey.getVersion(),
            signatureAlgorithm.getVaultSignatureAlgorithm(),
            signatureAlgorithm.getVaultHashAlgorithm(),
            data.flip(),
            sigBytes);
  }

  @Override
  protected void engineSetParameter(String s, Object o) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }
}
