package org.honton.chas.jca.vault.provider.oidc;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.SneakyThrows;
import org.honton.chas.jca.vault.provider.VaultProvider;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaKeyAlgorithm;
import org.honton.chas.jca.vault.provider.keygen.ecdsa.VaultEcdsaParameterSpec;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EcKeyUtil;
import org.jose4j.lang.JoseException;

public class ConnectProvider {

  private final EllipticCurveJsonWebKey ecjwk;
  @Getter private final OidcWellKnown.JsonWebKeySet jwks;

  private final long skew = 10;
  private final long lifetime = TimeUnit.DAYS.toSeconds(1);

  public ConnectProvider() throws JoseException {

    ECParameterSpec spec =
        new VaultEcdsaParameterSpec("Integration_Testing", VaultEcdsaKeyAlgorithm.ECDSA_P256);
    ecjwk = EcJwkGenerator.generateJwk(spec, VaultProvider.NAME, null);
    ecjwk.setKeyId(Long.toString(System.currentTimeMillis()));

    JsonWebKey jwk = new EllipticCurveJsonWebKey(ecjwk.getECPublicKey());
    jwk.setKeyId(ecjwk.getKeyId());

    jwks = new OidcWellKnown.JsonWebKeySet(List.of(jwk));
  }

  public static EllipticCurveJsonWebKey generateJwk(
      ECParameterSpec spec, String provider, SecureRandom secureRandom) throws JoseException {
    EcKeyUtil keyUtil = new EcKeyUtil(provider, secureRandom);
    KeyPair keyPair = keyUtil.generateKeyPair(spec);
    PublicKey publicKey = keyPair.getPublic();
    EllipticCurveJsonWebKey ecJwk =
        (EllipticCurveJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(publicKey);
    ecJwk.setPrivateKey(keyPair.getPrivate());
    return ecJwk;
  }

  public OidcWellKnown.Configuration getOpenIdProviderConfiguration(String issuer) {
    return OidcWellKnown.Configuration.builder()
        .issuer(issuer)
        .jwksUri(issuer + "/.well-known/jwks.json")
        .authorizationEndpoint("urn:proprietary:authorization")
        .responseTypesSupported(List.of("id_token"))
        .subjectTypesSupported(List.of("public"))
        .idTokenSigningAlgValuesSupported(List.of("ES256"))
        .claimsSupported(List.of("sub", "iss", "aud"))
        .build();
  }

  /**
   * Create a JWT for use
   *
   * @param issuer
   * @param audience
   * @param subject
   * @return
   */
  public String createJwt(String issuer, String audience, String subject) {
    JwtClaims claims = createClaims(issuer, audience, subject);
    return createTokenFromClaims(claims);
  }

  private JwtClaims createClaims(String issuer, String audience, String subject) {
    JwtClaims claims = new JwtClaims();
    claims.setIssuer(issuer);
    if (audience != null) {
      claims.setAudience(audience);
    }
    claims.setSubject(subject);
    claims.setGeneratedJwtId();

    long epochSecond = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
    claims.setIssuedAt(NumericDate.fromSeconds(epochSecond));
    claims.setNotBefore(NumericDate.fromSeconds(epochSecond - skew));
    claims.setExpirationTime(NumericDate.fromSeconds(epochSecond + lifetime));
    return claims;
  }

  @SneakyThrows
  private String createTokenFromClaims(JwtClaims claims) {
    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(claims.toJson());
    jws.setKey(ecjwk.getPrivateKey());
    jws.setKeyIdHeaderValue(ecjwk.getKeyId());
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

    return jws.getCompactSerialization();
  }
}
