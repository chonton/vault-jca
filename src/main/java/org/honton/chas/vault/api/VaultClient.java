package org.honton.chas.vault.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

@RequiredArgsConstructor
@EqualsAndHashCode
public class VaultClient implements VaultApi {

  private static final String VAULT_PREFIX = "vault:v";
  private static final int VAULT_PREFIX_LENGTH = VAULT_PREFIX.length();

  private static final String CONTENT_TYPE = "Content-Type";
  private static final String APPLICATION_JSON = "application/json";
  private static final String AUTHORIZATION = "Authorization";
  private static final String BEARER = "Bearer ";

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
  private static final HttpClient HTTP_CLIENT =
      HttpClient.newBuilder()
          .version(HttpClient.Version.HTTP_2)
          .connectTimeout(Duration.ofSeconds(10))
          .build();

  public static VaultClient INSTANCE =
      new VaultClient(getEnvOrProperty("VAULT_ADDR"), () -> getEnvOrProperty("VAULT_TOKEN"));

  private final String vaultAddress;
  private final Supplier<String> vaultTokenSupplier;

  static void setVaultInstance(String vaultAddress, Supplier<String> vaultToken) {
    INSTANCE = new VaultClient(vaultAddress, vaultToken);
  }

  private static String getEnvOrProperty(String name) {
    String value = System.getenv(name);
    return value == null || value.isEmpty() ? System.getProperty(name) : value;
  }

  private static String encodeUrl(String name) {
    return URLEncoder.encode(name, StandardCharsets.US_ASCII).replace("+", "%20");
  }

  @SneakyThrows
  private static BodyPublisher getBodyPublisher(Object request) {
    return HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(request));
  }

  private static String base64Encode(ByteBuffer data) {
    ByteBuffer encoded = Base64.getMimeEncoder().encode(data);
    return StandardCharsets.ISO_8859_1.decode(encoded).toString();
  }

  private static String base64Encode(byte[] predigested) {
    return new String(Base64.getMimeEncoder().encode(predigested), StandardCharsets.ISO_8859_1);
  }

  private static byte[] base64Decode(String data) {
    return Base64.getMimeDecoder().decode(data);
  }

  public static <T> T walkPath(Object result, String... pathSegments) {
    for (String pathSegment : pathSegments) {
      result = ((Map) result).get(pathSegment);
    }
    return (T) result;
  }

  @SneakyThrows
  private <T> T send(Builder builder, String url, String... pathSegments) {
    if (vaultAddress == null) {
      throw new IllegalStateException(
          "Set VAULT_ADDR environment or System property or invoke VaultApi.setVaultInstance()");
    }
    String vaultToken = vaultTokenSupplier.get();
    if (vaultToken == null) {
      throw new IllegalStateException(
          "Set VAULT_TOKEN environment or System property or invoke VaultApi.setVaultInstance()");
    }
    URI uri = URI.create(vaultAddress + url);
    HttpResponse<String> response =
        HTTP_CLIENT.send(
            builder
                .uri(uri)
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .header(AUTHORIZATION, BEARER + vaultToken)
                .build(),
            HttpResponse.BodyHandlers.ofString());
    if (200 > response.statusCode() || response.statusCode() > 300) {
      if (response.statusCode() == 404) {
        return null;
      }
      throw new IOException(response.statusCode() + " : " + response.body());
    }
    String body = response.body();
    if (body.isEmpty()) {
      return null;
    }
    Object result = OBJECT_MAPPER.readValue(body, Map.class);
    return walkPath(result, pathSegments);
  }

  private <T> T post(String url, Object request, String... pathSegments) {
    return send(HttpRequest.newBuilder().POST(getBodyPublisher(request)), url, pathSegments);
  }

  @Override
  public List<String> listKeys() {
    Builder request = HttpRequest.newBuilder().method("LIST", BodyPublishers.noBody());
    List<String> list = send(request, "/v1/transit/keys", "data", "keys");
    return list != null ? list : List.of();
  }

  @Override
  public void createKey(String name, String keyType, String autoRotationPeriod) {
    post(
        "/v1/transit/keys/" + encodeUrl(name),
        Map.of("type", keyType, "duration", autoRotationPeriod));
  }

  @Override
  public Map<String, Object> readKey(String name) {
    String url = "/v1/transit/keys/" + encodeUrl(name);
    return send(HttpRequest.newBuilder().GET(), url, "data");
  }

  @Override
  public byte[] signData(
      String name, int version, String signatureAlgorithm, String hashAlgorithm, ByteBuffer data) {
    String input = base64Encode(data);
    Map<String, Serializable> body =
        signatureAlgorithm != null
            ? Map.of(
                "input", input, "signature_algorithm", signatureAlgorithm, "salt_length", "hash")
            : Map.of("input", input, "salt_length", "hash");
    String signature =
        post(
            "/v1/transit/sign/" + encodeUrl(name) + "/" + hashAlgorithm, body, "data", "signature");
    String interesting = extractSignature(signature);
    return base64Decode(interesting);
  }

  private String extractSignature(String signature) {
    int last = signature.length();
    while (signature.charAt(last - 1) == '=') {
      --last;
    }
    return signature.substring(signature.indexOf(':', VAULT_PREFIX_LENGTH) + 1, last);
  }

  @Override
  public boolean verifySignedData(
      String name,
      int version,
      String sa,
      String hashAlgorithm,
      ByteBuffer data,
      byte[] signature) {

    String in = base64Encode(data);
    String vs = VAULT_PREFIX + version + ":" + base64Encode(signature);
    Map<String, Serializable> body =
        sa != null
            ? Map.of("input", in, "signature", vs, "signature_algorithm", sa, "salt_length", "hash")
            : Map.of("input", in, "signature", vs, "salt_length", "hash");
    return post(
        "/v1/transit/verify/" + encodeUrl(name) + "/" + hashAlgorithm, body, "data", "valid");
  }
}
