package org.honton.chas.jca.vault.provider.keystore;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;
import org.honton.chas.jca.vault.provider.keygen.VaultKeyFactory;
import org.honton.chas.vault.api.VaultApi;
import org.honton.chas.vault.api.VaultClient;

public class VaultKeyStore extends KeyStoreSpi {

  public VaultKeyStore() {}

  private static <T> T noSupportForCertificates() {
    throw new UnsupportedOperationException("No support for certificates");
  }

  private static <T> T noSupportForUpdate() {
    throw new UnsupportedOperationException("No support for update or delete");
  }

  protected VaultApi getVaultInstance() {
    return VaultClient.INSTANCE;
  }

  /**
   * Lists all the alias names of this keystore.
   *
   * @return enumeration of the alias names
   */
  @Override
  public Enumeration<String> engineAliases() {
    return Collections.enumeration(getVaultInstance().listKeys());
  }

  /**
   * Checks if the given alias exists in this keystore.
   *
   * @param alias the alias name
   * @return true if the alias exists, false otherwise
   */
  @Override
  public boolean engineContainsAlias(String alias) {
    return getVaultInstance().readKey(alias) != null;
  }

  /**
   * Retrieves the number of entries in this keystore.
   *
   * @return the number of entries in this keystore
   */
  @Override
  public int engineSize() {
    return getVaultInstance().listKeys().size();
  }

  /**
   * Returns the key associated with the given alias, using the given password to recover it. The
   * key must have been associated with the alias by a call to {@code setKeyEntry}, or by a call to
   * {@code setEntry} with a {@code PrivateKeyEntry} or {@code SecretKeyEntry}.
   *
   * @param alias the alias name
   * @param password the password for recovering the key
   * @return the requested key, or null if the given alias does not exist or does not identify a
   *     key-related entry.
   * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
   * @throws UnrecoverableKeyException if the key cannot be recovered (e.g., the given password is
   *     wrong).
   */
  public Key engineGetKey(String alias, char[] password) {
    Map<String, Object> result = getVaultInstance().readKey(alias);
    if (result == null) {
      return null;
    }

    return VaultKeyFactory.wrapPublicKey(alias, result);
  }

  @Override
  public void engineLoad(InputStream inputStream, char[] chars) {
    // ignore the load
  }

  @Override
  public Certificate[] engineGetCertificateChain(String s) {
    return noSupportForCertificates();
  }

  @Override
  public Certificate engineGetCertificate(String s) {
    return noSupportForCertificates();
  }

  /**
   * Returns the creation date of the entry identified by the given alias.
   *
   * @param alias the alias name
   * @return the creation date of this entry, or null if the given alias does not exist
   */
  @Override
  public Date engineGetCreationDate(String alias) {
    Map<String, Object> result = getVaultInstance().readKey(alias);
    if (result == null) {
      return null;
    }
    Entry<String, Map<String, String>> latestKey = VaultKeyFactory.latestKey(result);
    return Date.from(Instant.parse(VaultApi.walkPath(latestKey.getValue(), "creation_time")));
  }

  @Override
  public void engineSetKeyEntry(String s, Key key, char[] chars, Certificate[] certificates) {
    noSupportForUpdate();
  }

  @Override
  public void engineSetKeyEntry(String s, byte[] bytes, Certificate[] certificates) {
    noSupportForUpdate();
  }

  @Override
  public void engineSetCertificateEntry(String s, Certificate certificate) {
    noSupportForCertificates();
  }

  @Override
  public void engineDeleteEntry(String s) {
    noSupportForUpdate();
  }

  @Override
  public boolean engineIsKeyEntry(String s) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean engineIsCertificateEntry(String s) {
    return noSupportForCertificates();
  }

  @Override
  public String engineGetCertificateAlias(Certificate certificate) {
    return noSupportForCertificates();
  }

  @Override
  public void engineStore(OutputStream outputStream, char[] chars) {
    throw new UnsupportedOperationException("No support for export");
  }
}
