package org.honton.chas.jca.vault.provider.signature;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import lombok.SneakyThrows;
import org.honton.chas.jca.vault.provider.VaultPrivateKey;
import org.honton.chas.jca.vault.provider.VaultPublicKey;
import org.honton.chas.vault.api.VaultApi;

public class VaultSignature extends SignatureSpi {

  private final VaultApi vaultApi;
  private final SignatureAlgorithm signatureAlgorithm;
  private final MessageDigest predigested;
  private boolean inProgress;

  private VaultPublicKey vaultPublicKey;
  private VaultPrivateKey vaultPrivateKey;

  @SneakyThrows
  public VaultSignature(VaultApi vaultApi, SignatureAlgorithm signatureAlgorithm) {
    this.vaultApi = vaultApi;
    this.signatureAlgorithm=signatureAlgorithm;
    predigested = MessageDigest.getInstance(signatureAlgorithm.getJcaDigestAlgorithm());
  }

  /**
   * Initializes this signature object with the specified public key for verification operations.
   *
   * @param publicKey the public key of the identity whose signature is going to be verified.
   * @throws InvalidKeyException if the key is improperly encoded, parameters are missing, and so
   *     on.
   */
  @Override
  protected void engineInitVerify(PublicKey publicKey) {
    vaultPublicKey = (VaultPublicKey) publicKey;
    resetDigest();
  }

  /**
   * Initializes this signature object with the specified private key for signing operations.
   *
   * @param privateKey the private key of the identity whose signature will be generated.
   * @throws InvalidKeyException if the key is improperly encoded, parameters are missing, and so
   *     on.
   */
  @Override
  protected void engineInitSign(PrivateKey privateKey) {
    vaultPrivateKey = (VaultPrivateKey) privateKey;
    resetDigest();
  }

  /**
   * Updates the data to be signed or verified using the specified byte.
   *
   * @param b the byte to use for the update.
   * @throws SignatureException if the engine is not initialized properly.
   */
  @Override
  protected void engineUpdate(byte b) {
    predigested.update(b);
    inProgress = true;
  }

  /**
   * Updates the data to be signed or verified, using the specified array of bytes, starting at the
   * specified offset.
   *
   * @param b the array of bytes
   * @param off the offset to start from in the array of bytes
   * @param len the number of bytes to use, starting at offset
   * @throws SignatureException if the engine is not initialized properly
   */
  @Override
  protected void engineUpdate(byte[] b, int off, int len) {
    predigested.update(b, off, len);
    inProgress = true;
  }

  /**
   * Returns the signature bytes of all the data updated so far. The format of the signature depends
   * on the underlying signature scheme.
   *
   * @return the signature bytes of the signing operation's result.
   * @throws SignatureException if the engine is not initialized properly or if this signature
   *     algorithm is unable to process the input data provided.
   */
  @Override
  protected byte[] engineSign() {
    return vaultApi.signData(vaultPrivateKey.getName(), vaultPrivateKey.getVersion(),
        signatureAlgorithm.getVaultSignatureAlgorithm(),
        signatureAlgorithm.getVaultHashAlgorithm(), getPredigested());
  }

  /**
   * Verifies the passed-in signature.
   *
   * @param sigBytes the signature bytes to be verified.
   * @return true if the signature was verified, false if not.
   * @throws SignatureException if the engine is not initialized properly, the passed-in signature
   *     is improperly encoded or of the wrong type, if this signature algorithm is unable to
   *     process the input data provided, etc.
   */
  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    return vaultApi.verifySignedData(
        vaultPublicKey.getName(),
        vaultPublicKey.getVersion(),
        signatureAlgorithm.getVaultSignatureAlgorithm(),
        signatureAlgorithm.getVaultHashAlgorithm(),
        getPredigested(), sigBytes);
  }

  @Override
  protected void engineSetParameter(String s, Object o) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  @Override
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  private void resetDigest() {
    if (inProgress) {
      predigested.reset();
      inProgress = false;
    }
  }

  private byte[] getPredigested() {
    inProgress = false;
    return predigested.digest();
  }
}
