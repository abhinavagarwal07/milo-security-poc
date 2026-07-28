/*
 * UASC pre-authentication memory-leak PoC: victim server.
 *
 * A minimal, otherwise-unremarkable Eclipse Milo OPC UA server (None + Basic256Sha256
 * endpoints at opc.tcp://<host>:12686/milo, default config, default RateLimitingHandler,
 * default UASC chunk/connection limits -- nothing tuned to make the attack easier).
 * Built against whichever `milo.version` this jar was compiled for: 1.1.4 (vulnerable,
 * the default) or 1.1.5 (fixed, the negative control). Identical code either way -- only
 * the Milo jars on the classpath differ.
 *
 * A background reporter thread prints Netty's pooled DIRECT memory usage once per second
 * ("MEM ..." lines) so an external script can graph the leak and detect saturation without
 * attaching a profiler.
 *
 * A second, completely independent background thread ("HEARTBEAT ...") -- a bare counter
 * with no Netty, no OPC UA, no shared state with the request-handling path -- is started
 * alongside it to stand in for an unrelated co-located workload in the same JVM (e.g. a
 * metrics exporter, a scheduled job, another protocol handler). If this leak crashes the
 * whole process, the heartbeat dies with it even though it never touched the vulnerable
 * code path, which is the point: the blast radius is the entire process, not just OPC UA
 * connection handling.
 */
package poc;

import static org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.PooledByteBufAllocatorMetric;
import io.netty.util.internal.PlatformDependent;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaRuntimeException;
import org.eclipse.milo.opcua.stack.core.security.DefaultApplicationGroup;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultServerCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.FileBasedCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.FileBasedTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.KeyStoreCertificateStore;
import org.eclipse.milo.opcua.stack.core.security.RsaSha256CertificateFactory;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import org.eclipse.milo.opcua.stack.core.util.NonceUtil;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;
import org.slf4j.LoggerFactory;

public class VictimServer {

  private static final int TCP_BIND_PORT = 12686;

  static {
    Security.addProvider(new BouncyCastleProvider());
    try {
      NonceUtil.blockUntilSecureRandomSeeded(10, java.util.concurrent.TimeUnit.SECONDS);
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(-1);
    }
  }

  public static void main(String[] args) throws Exception {
    OpcUaServer server = buildServer();

    server.startup().get();

    long pid = ProcessHandle.current().pid();
    startMemoryReporter();
    startHeartbeat();

    // Emitted AFTER the reporter/heartbeat threads are running so the harness scripts can
    // rely on it.
    System.out.println("POC_SERVER_READY pid=" + pid + " miloVersion=" + OpcUaServer.SDK_VERSION);
    System.out.flush();

    CompletableFuture<Void> shutdown = new CompletableFuture<>();
    Runtime.getRuntime().addShutdownHook(new Thread(() -> shutdown.complete(null)));
    shutdown.get();
  }

  private static OpcUaServer buildServer() throws Exception {
    Path securityTempDir = Paths.get(System.getProperty("java.io.tmpdir"), "victim-server", "security");
    Files.createDirectories(securityTempDir);

    Path pkiDir = securityTempDir.resolve("pki");

    KeyStoreLoader loader = new KeyStoreLoader().load(securityTempDir);

    var certificateStore =
        KeyStoreCertificateStore.createAndInitialize(
            new KeyStoreCertificateStore.Settings(
                securityTempDir.resolve("victim-server.pfx"),
                "password"::toCharArray,
                alias -> "password".toCharArray()));

    var trustListManager = FileBasedTrustListManager.createAndInitialize(pkiDir);

    var certificateQuarantine =
        FileBasedCertificateQuarantine.create(pkiDir.resolve("rejected").resolve("certs"));

    var certificateFactory =
        new RsaSha256CertificateFactory() {
          @Override
          protected KeyPair createRsaSha256KeyPair() {
            return loader.getServerKeyPair();
          }

          @Override
          protected X509Certificate[] createRsaSha256CertificateChain(KeyPair keyPair) {
            return loader.getServerCertificateChain();
          }
        };

    var certificateValidator =
        new DefaultServerCertificateValidator(trustListManager, certificateQuarantine);

    var defaultGroup =
        DefaultApplicationGroup.createAndInitialize(
            trustListManager, certificateStore, certificateFactory, certificateValidator);

    var certificateManager = new DefaultCertificateManager(certificateQuarantine, defaultGroup);

    X509Certificate certificate = loader.getServerCertificate();

    String applicationUri =
        CertificateUtil.getSanUri(certificate)
            .orElseThrow(
                () ->
                    new UaRuntimeException(
                        StatusCodes.Bad_ConfigurationError,
                        "certificate is missing the application URI"));

    Set<EndpointConfig> endpointConfigs = createEndpointConfigs(certificate);

    OpcUaServerConfig serverConfig =
        OpcUaServerConfig.builder()
            .setApplicationUri(applicationUri)
            .setApplicationName(LocalizedText.english("Milo PoC Victim Server"))
            .setEndpoints(endpointConfigs)
            .setBuildInfo(
                new BuildInfo(
                    "urn:memory-leak:victim-server",
                    "milo-security-poc",
                    "milo poc victim server",
                    OpcUaServer.SDK_VERSION,
                    "",
                    DateTime.now()))
            .setCertificateManager(certificateManager)
            // Anonymous-only identity validator; authentication is irrelevant to this
            // pre-authentication attack, which never gets past OpenSecureChannel.
            .setIdentityValidator(AnonymousIdentityValidator.INSTANCE)
            .setProductUri("urn:memory-leak:victim-server")
            .build();

    return new OpcUaServer(
        serverConfig,
        transportProfile -> {
          assert transportProfile == TransportProfile.TCP_UASC_UABINARY;
          return new OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build());
        });
  }

  private static Set<EndpointConfig> createEndpointConfigs(X509Certificate certificate) {
    var endpointConfigs = new LinkedHashSet<EndpointConfig>();

    var hostnames = new LinkedHashSet<String>();
    hostnames.add(HostnameUtil.getHostname());
    hostnames.addAll(HostnameUtil.getHostnames("0.0.0.0", true, false));

    for (String hostname : hostnames) {
      EndpointConfig.Builder builder =
          EndpointConfig.newBuilder()
              .setBindAddress("0.0.0.0")
              .setHostname(hostname)
              .setPath("/milo")
              .setCertificate(certificate)
              .addTokenPolicies(USER_TOKEN_POLICY_ANONYMOUS)
              .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
              .setBindPort(TCP_BIND_PORT);

      endpointConfigs.add(
          builder.copy().setSecurityPolicy(SecurityPolicy.None).setSecurityMode(MessageSecurityMode.None).build());

      endpointConfigs.add(
          builder
              .copy()
              .setSecurityPolicy(SecurityPolicy.Basic256Sha256)
              .setSecurityMode(MessageSecurityMode.SignAndEncrypt)
              .build());
    }

    return endpointConfigs;
  }

  private static void startMemoryReporter() {
    Thread t =
        new Thread(
            () -> {
              PooledByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
              PooledByteBufAllocatorMetric m = alloc.metric();
              while (true) {
                try {
                  long usedDirect = PlatformDependent.usedDirectMemory();
                  long maxDirect = PlatformDependent.maxDirectMemory();
                  long pinned = alloc.pinnedDirectMemory();
                  long arenaUsed = m.usedDirectMemory();
                  long ts = System.currentTimeMillis();
                  System.out.printf(
                      "MEM ts=%d usedDirectBytes=%d pinnedDirectBytes=%d arenaUsedDirectBytes=%d"
                          + " maxDirectBytes=%d%n",
                      ts, usedDirect, pinned, arenaUsed, maxDirect);
                  System.out.flush();
                  Thread.sleep(1000);
                } catch (InterruptedException e) {
                  return;
                } catch (Throwable t2) {
                  System.out.println("MEM reporter error: " + t2);
                  System.out.flush();
                }
              }
            },
            "mem-reporter");
    t.setDaemon(true);
    t.start();
  }

  /**
   * A stand-in for an unrelated co-located workload in the same JVM: a bare counter/timer
   * with zero dependency on Netty, OPC UA, or anything the attack touches. Its only purpose
   * is to keep incrementing and logging once a second for as long as the process is alive,
   * so that its disappearance (no further "HEARTBEAT" lines after a given sequence number)
   * is unambiguous evidence that the *entire process* went down, not just OPC UA request
   * handling -- i.e. that this is a process-wide blast radius, not a per-connection failure.
   */
  private static void startHeartbeat() {
    Thread t =
        new Thread(
            () -> {
              long seq = 0;
              while (true) {
                try {
                  System.out.printf(
                      "HEARTBEAT seq=%d ts=%d%n", seq++, System.currentTimeMillis());
                  System.out.flush();
                  Thread.sleep(1000);
                } catch (InterruptedException e) {
                  return;
                }
              }
            },
            "unrelated-heartbeat-workload");
    t.setDaemon(true);
    t.start();
  }
}
