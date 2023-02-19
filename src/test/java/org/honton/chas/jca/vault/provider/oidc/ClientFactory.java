package org.honton.chas.jca.vault.provider.oidc;

import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import lombok.experimental.UtilityClass;

@UtilityClass
public class ClientFactory {

  public HttpClient createClient() throws GeneralSecurityException {
    return HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_2)
        .connectTimeout(Duration.ofSeconds(10))
        .sslContext(acceptAnyCertificate())
        .build();
  }

  private SSLContext acceptAnyCertificate() throws GeneralSecurityException {
    System.getProperties()
        .setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");

    SSLContext sc = SSLContext.getInstance("tlsv1.2");
    sc.init(
        null,
        new TrustManager[] {
          new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] xcs, String string) {}

            public void checkServerTrusted(X509Certificate[] xcs, String string) {}

            public X509Certificate[] getAcceptedIssuers() {
              return null;
            }
          }
        },
        null);
    return sc;
  }

  public SSLSocketFactory createSslSocketFactory() throws GeneralSecurityException {
    return acceptAnyCertificate().getSocketFactory();
  }

  public HostnameVerifier createHostnameVerifier() {
    return (hostname, session) -> true;
  }
}
