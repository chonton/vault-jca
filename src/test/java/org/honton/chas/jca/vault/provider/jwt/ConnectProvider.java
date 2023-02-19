package org.honton.chas.jca.vault.provider.jwt;

import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.SneakyThrows;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

public class ConnectProvider {

  private final EllipticCurveJsonWebKey ecjwk;
  private final JsonWebKey jwk;
  @Getter private final OidcWellKnown.JsonWebKeySet jwks;

  private final long skew = 10;
  private final long lifetime = TimeUnit.DAYS.toSeconds(1);

  public ConnectProvider() throws JoseException {
    ecjwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
    ecjwk.setKeyId(Long.toString(System.currentTimeMillis()));

    jwk = new EllipticCurveJsonWebKey(ecjwk.getECPublicKey());
    jwk.setKeyId(ecjwk.getKeyId());

    jwks = new OidcWellKnown.JsonWebKeySet(List.of(jwk));
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
