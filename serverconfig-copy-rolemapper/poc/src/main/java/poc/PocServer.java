/*
 * the RoleMapper-drop defect PoC: server harness -- four causal controls, identical application code.
 *
 * Models an embedding application that (a) wants RBAC enforced -- it attaches a RoleMapper to
 * its OpcUaServerConfig mapping anonymous clients to a non-privileged ObserverRole and the
 * username "admin" to AdminRole -- and (b) builds the config it actually hands to the running
 * OpcUaServer via OpcUaServerConfig.copy(), a common pattern for embedding frameworks/wrappers
 * that need to layer their own defaults on top of a caller-supplied config.
 *
 * On Milo 1.0.0-1.1.4, OpcUaServerConfig.copy() never carries the RoleMapper into the builder
 * it returns, so the RoleMapper attached to the base config above is silently dropped from the
 * config the server actually runs with. Milo's DefaultAccessController treats "no RoleMapper"
 * as "nothing to check" for RolePermissions-gated operations (Browse, Call, RolePermissions/
 * Historizing attribute reads, AddNodes/DeleteNodes) -- so RBAC fails open and every identity,
 * anonymous included, is granted access to operations that were supposed to require AdminRole.
 *
 * Fixed in Milo 1.1.5, commit d51f03e9a ("Preserve role mappings when copying server config",
 * PR #1801): copy() now does `config.getRoleMapper().ifPresent(builder::setRoleMapper);`.
 *
 * To prove the MISSING MAPPER -- not identity setup, harness behavior, or anything else -- is
 * the sole cause, this class supports four modes selected by argv[0], with every other line of
 * code identical across them:
 *
 *   original -- baseConfig used directly, no copy() at all. CONTROL: Call must be DENIED.
 *   copied   -- baseConfig routed through OpcUaServerConfig.copy(base, b -> {}) with no further
 *               changes. THE DEFECT: on vulnerable Milo (<= 1.1.4) this drops the RoleMapper,
 *               so Call is ALLOWED. This is the only mode/version combination where the bug
 *               manifests.
 *   restored -- the SAME copy(base, consumer) call as "copied", but the consumer explicitly
 *               re-applies b.setRoleMapper(ROLE_MAPPER). CAUSAL CLINCHER: identical to "copied"
 *               in every other respect (same base config, same copy() call, same Milo build) --
 *               isolates the mapper's presence/absence as the ONLY variable. Call must be
 *               DENIED again, exactly like "original".
 *   fixed    -- identical source code to "copied" (config IS routed through copy()), but
 *               meaningful only when this class is run against the FIXED Milo 1.1.5 jar, where
 *               copy() itself now preserves the RoleMapper. Call must be DENIED (regression
 *               check on the real upstream fix, not a workaround).
 *
 * Combined with which Milo version this class is run against (see ../run.sh, which builds this
 * exact source twice: default ${milo.version}=1.1.4 and -Dmilo.version=1.1.5), this gives the
 * four causal controls:
 *   1. original,  1.1.4 -> denied    (RoleMapper present, no copy() involved)
 *   2. copied,    1.1.4 -> ALLOWED   (the bug)
 *   3. restored,  1.1.4 -> denied    (mapper explicitly restored after copy() -- isolates cause)
 *   4. copied,    1.1.5 -> denied    (upstream fix: copy() itself preserves the mapper)
 *
 * Prints POC_SERVER_CONFIG with roleMapperPresentOnBaseConfig/roleMapperPresentOnRunningConfig
 * so the difference is directly observable, then POC_SERVER_READY once listening.
 *
 * argv: [mode] [port]   mode in {original, copied, restored, fixed}, default "copied"
 *                       port default 12686
 */
package poc;

import static org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;
import static org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig.USER_TOKEN_POLICY_USERNAME;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfigBuilder;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfigLimits;
import org.eclipse.milo.opcua.sdk.server.RoleMapper;
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.Identity;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.security.DefaultApplicationGroup;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultServerCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateStore;
import org.eclipse.milo.opcua.stack.core.security.MemoryTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.RsaSha256CertificateFactory;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;

public class PocServer {

  public static final String ADMIN_USERNAME = "admin";
  public static final String ADMIN_PASSWORD = "adminpass123";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * The RoleMapper the embedding application intends: username "admin" -> AdminRole, every
   * other identity (anonymous included) -> ObserverRole only. This is set on the base config
   * below; whether it survives onto the config the server actually runs with is exactly what
   * the RoleMapper-drop defect is about.
   */
  private static final RoleMapper ROLE_MAPPER =
      new RoleMapper() {
        @Override
        public List<org.eclipse.milo.opcua.stack.core.types.builtin.NodeId> getRoleIds(
            Identity identity) {
          if (identity instanceof Identity.UsernameIdentity u
              && ADMIN_USERNAME.equals(u.getUsername())) {
            return List.of(ControlNamespace.ADMIN_ROLE);
          }
          return List.of(ControlNamespace.OBSERVER_ROLE);
        }

        @Override
        public List<org.eclipse.milo.opcua.stack.core.types.builtin.NodeId> getRoleIds(
            Identity identity, String applicationUri, EndpointDescription endpoint) {
          return getRoleIds(identity);
        }
      };

  public static void main(String[] args) throws Exception {
    String mode = args.length > 0 ? args[0] : "copied";
    int port = args.length > 1 ? Integer.parseInt(args[1]) : 12686;

    if (!List.of("original", "copied", "restored", "fixed").contains(mode)) {
      throw new IllegalArgumentException(
          "mode must be one of original|copied|restored|fixed, got: " + mode);
    }

    String hostname = HostnameUtil.getHostname();
    String applicationUri = "urn:rolemapper:poc-server:" + mode;

    KeyPair keyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);
    SelfSignedCertificateBuilder certBuilder = new SelfSignedCertificateBuilder(keyPair);
    certBuilder.setCommonName("the RoleMapper-drop defect PoC Server");
    certBuilder.setApplicationUri(applicationUri);
    certBuilder.addDnsName(hostname);
    certBuilder.addDnsName("localhost");
    certBuilder.addIpAddress("127.0.0.1");
    X509Certificate certificate = certBuilder.build();
    X509Certificate[] certificateChain = new X509Certificate[] {certificate};

    var trustListManager = new MemoryTrustListManager();
    var certificateStore = new MemoryCertificateStore();
    var certificateQuarantine = new MemoryCertificateQuarantine();

    var certificateFactory =
        new RsaSha256CertificateFactory() {
          @Override
          protected KeyPair createRsaSha256KeyPair() {
            return keyPair;
          }

          @Override
          protected X509Certificate[] createRsaSha256CertificateChain(KeyPair kp) {
            return certificateChain;
          }
        };

    var certificateValidator =
        new DefaultServerCertificateValidator(trustListManager, certificateQuarantine);

    var defaultGroup =
        DefaultApplicationGroup.createAndInitialize(
            trustListManager, certificateStore, certificateFactory, certificateValidator);

    var certificateManager = new DefaultCertificateManager(certificateQuarantine, defaultGroup);

    Set<EndpointConfig> endpoints = new LinkedHashSet<>();
    endpoints.add(
        EndpointConfig.newBuilder()
            .setBindAddress("0.0.0.0")
            .setHostname(hostname)
            .setPath("/poc")
            .setCertificate(certificate)
            .addTokenPolicies(USER_TOKEN_POLICY_ANONYMOUS, USER_TOKEN_POLICY_USERNAME)
            .setSecurityPolicy(SecurityPolicy.None)
            .setSecurityMode(MessageSecurityMode.None)
            .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
            .setBindPort(port)
            .build());

    var usernameIdentityValidator =
        new UsernameIdentityValidator(
            challenge ->
                ADMIN_USERNAME.equals(challenge.getUsername())
                    && ADMIN_PASSWORD.equals(challenge.getPassword()));

    OpcUaServerConfigBuilder baseBuilder =
        OpcUaServerConfig.builder()
            .setApplicationUri(applicationUri)
            .setApplicationName(LocalizedText.english("the RoleMapper-drop defect PoC Server"))
            .setEndpoints(endpoints)
            .setBuildInfo(
                new BuildInfo(
                    "urn:rolemapper:poc-server",
                    "eclipse",
                    "rolemapper poc server",
                    OpcUaServer.SDK_VERSION,
                    "",
                    DateTime.now()))
            .setCertificateManager(certificateManager)
            .setIdentityValidator(
                new CompositeValidator(
                    AnonymousIdentityValidator.INSTANCE, usernameIdentityValidator))
            .setProductUri("urn:rolemapper:poc-server:product")
            .setLimits(new OpcUaServerConfigLimits() {})
            // The embedding app's intent: RBAC IS configured.
            .setRoleMapper(ROLE_MAPPER);

    OpcUaServerConfig baseConfig = baseBuilder.build();

    // *** THE FOUR CAUSAL CONTROLS -- identical application code, only this branch differs ***
    OpcUaServerConfig finalConfig;
    switch (mode) {
      case "original" ->
          // CONTROL 1: no copy() at all. RoleMapper set directly on the config the server runs
          // with. This is the non-buggy baseline every other mode is compared against.
          finalConfig = baseConfig;
      case "copied", "fixed" ->
          // CONTROL 2 (mode=copied, run against vulnerable 1.1.4): THE DEFECT. copy() never
          // calls builder.setRoleMapper(config.getRoleMapper()...), so the RoleMapper set above
          // is silently dropped from finalConfig.
          // CONTROL 4 (mode=fixed, run against fixed 1.1.5): identical source line, but on the
          // fixed jar copy() itself (commit d51f03e9a) now preserves the mapper.
          finalConfig = OpcUaServerConfig.copy(baseConfig, b -> {});
      case "restored" ->
          // CONTROL 3, the causal clincher: the SAME copy(base, consumer) call as "copied",
          // with nothing else different -- same base config, same Milo build -- except the
          // consumer explicitly re-applies the RoleMapper that copy() would otherwise drop.
          // If Call goes back to being denied here, the mapper's presence/absence is proven to
          // be the sole variable, not some other side effect of copy() or of this harness.
          finalConfig = OpcUaServerConfig.copy(baseConfig, b -> b.setRoleMapper(ROLE_MAPPER));
      default -> throw new IllegalStateException("unreachable, mode already validated: " + mode);
    }

    boolean roleMapperOnBase = baseConfig.getRoleMapper().isPresent();
    boolean roleMapperOnRunning = finalConfig.getRoleMapper().isPresent();
    System.out.println(
        "POC_SERVER_CONFIG mode="
            + mode
            + " roleMapperPresentOnBaseConfig="
            + roleMapperOnBase
            + " roleMapperPresentOnRunningConfig="
            + roleMapperOnRunning
            + " ("
            + (roleMapperOnRunning
                ? "PRESERVED -- RBAC enforced on the running server"
                : "DROPPED by OpcUaServerConfig.copy() -- RBAC fails open on the running server"
                    + " (the RoleMapper-drop defect)")
            + ")");
    System.out.flush();

    OpcUaServer server =
        new OpcUaServer(
            finalConfig,
            transportProfile -> {
              if (transportProfile == TransportProfile.TCP_UASC_UABINARY) {
                return new OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build());
              }
              throw new RuntimeException("unexpected TransportProfile: " + transportProfile);
            });

    ControlNamespace namespace = new ControlNamespace(server);
    namespace.startup();

    server.startup().get();

    long pid = ProcessHandle.current().pid();
    System.out.println(
        "POC_SERVER_READY mode="
            + mode
            + " pid="
            + pid
            + " hostname="
            + hostname
            + " port="
            + port
            + " endpointUrl=opc.tcp://"
            + hostname
            + ":"
            + port
            + "/poc"
            + " roleMapperPresentOnRunningConfig="
            + roleMapperOnRunning);
    System.out.flush();

    Thread.currentThread().join();
  }
}
