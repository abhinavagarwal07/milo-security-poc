package poc;

import java.security.SecureRandom;
import java.util.Properties;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import poc.common.Args;
import poc.common.EmbeddedServerFactory;
import poc.common.PropsFile;
import poc.common.WireCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Process 1 of 5: the vulnerable (or, built against milo.version=1.1.5, fixed) Milo server.
 *
 * <p>This process is the only one, together with {@link VictimMain}, that ever holds the
 * victim's actual password -- it must, to authenticate the victim. It is launched with
 * {@code --password} supplied directly by the orchestrating shell script ({@code run.sh}),
 * which generates it at runtime; the password never appears in {@link AttackerMain}'s argv,
 * environment, or any file it reads.
 */
public class ServerMain {

  private static final Logger LOGGER = LoggerFactory.getLogger(ServerMain.class);

  public static void main(String[] args) throws Exception {
    Args a = Args.parse(args);
    String username = a.require("username");
    String password = a.require("password");
    String policyId = a.get("policy-id", "username_rsa15");
    int port = a.getInt("port", 20000 + new SecureRandom().nextInt(20000));
    String infoFile = a.require("info-file");

    EmbeddedServerFactory.Built built =
        EmbeddedServerFactory.startServer(port, username, password, policyId);
    OpcUaServer server = built.server;
    server.startup().get();

    String endpointUrl = "opc.tcp://localhost:" + port + "/test";
    String certFingerprint = WireCodec.certFingerprintSha256(built.certificate);

    Properties info = new Properties();
    info.setProperty("port", Integer.toString(port));
    info.setProperty("endpointUrl", endpointUrl);
    info.setProperty("certFingerprint", certFingerprint);
    info.setProperty("username", username);
    info.setProperty("policyId", policyId);
    PropsFile.store(java.nio.file.Path.of(infoFile), info, "the padding oracle PoC server info (no password)");

    LOGGER.info("[+] Server listening at {}", endpointUrl);
    LOGGER.info("[+] Server certificate SHA-256: {}", certFingerprint);
    System.out.println("SERVER_READY endpointUrl=" + endpointUrl + " certFingerprint=" + certFingerprint);

    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  try {
                    server.shutdown().get();
                  } catch (Exception ignore) {
                  }
                }));

    // Block until killed (SIGTERM from run.sh) -- this process intentionally never exits on its own.
    Thread.currentThread().join();
  }
}
