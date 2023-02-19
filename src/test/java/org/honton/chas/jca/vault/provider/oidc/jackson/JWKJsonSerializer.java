package org.honton.chas.jca.vault.provider.oidc.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import java.io.IOException;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;

public class JWKJsonSerializer extends StdSerializer<JsonWebKey> {
  public JWKJsonSerializer() {
    super(JsonWebKey.class);
  }

  @Override
  public void serialize(
      JsonWebKey jsonWebKey, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
      throws IOException {
    jsonGenerator.writeObject(jsonWebKey.toParams(OutputControlLevel.INCLUDE_SYMMETRIC));
  }
}
