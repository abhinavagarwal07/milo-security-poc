package poc.common;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.Set;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfigLimits;
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
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
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;

/**
 * Builds the standalone, embedded the padding oracle PoC server: a real {@link OpcUaServer} with a
 * Basic128Rsa15 username {@link UserTokenPolicy} alongside anonymous access, using only public
 * sdk-server/stack-core API (Milo's own test-scope {@code TestServer} is unavailable from the
 * released jars this PoC depends on).
 */
public final class EmbeddedServerFactory {

  private EmbeddedServerFactory() {}

  public static final class Built {
    public final OpcUaServer server;
    public final X509Certificate certificate;

    public Built(OpcUaServer server, X509Certificate certificate) {
      this.server = server;
      this.certificate = certificate;
    }
  }

  public static Built startServer(int port, String username, String password, String policyId)
      throws Exception {
    KeyPair keyPair = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);
    X509Certificate certificate =
        new SelfSignedCertificateBuilder(keyPair)
            .setCommonName("the padding oracle PoC Server")
            .setOrganization("milo-security-poc")
            .setOrganizationalUnit("research")
            .setLocalityName("N/A")
            .setStateName("N/A")
            .setCountryCode("US")
            .setApplicationUri("urn:milo:poc:padding-oracle:server")
            .addDnsName("localhost")
            .addIpAddress("127.0.0.1")
            .build();

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
            return new X509Certificate[] {certificate};
          }
        };

    var certificateValidator =
        new DefaultServerCertificateValidator(trustListManager, certificateQuarantine);
    var defaultGroup =
        DefaultApplicationGroup.createAndInitialize(
            trustListManager, certificateStore, certificateFactory, certificateValidator);
    var certificateManager = new DefaultCertificateManager(certificateQuarantine, defaultGroup);

    UsernameIdentityValidator usernameIdentityValidator =
        new UsernameIdentityValidator(
            challenge ->
                username.equals(challenge.getUsername()) && password.equals(challenge.getPassword()));

    String applicationUri =
        CertificateUtil.getSanUri(certificate)
            .orElseThrow(() -> new IllegalStateException("certificate is missing the application URI"));

    Set<EndpointConfig> endpointConfigurations = createEndpointConfigs(certificate, port, policyId);

    OpcUaServerConfig serverConfig =
        OpcUaServerConfig.builder()
            .setApplicationUri(applicationUri)
            .setApplicationName(LocalizedText.english("the padding oracle PoC Server"))
            .setEndpoints(endpointConfigurations)
            .setBuildInfo(
                new BuildInfo(
                    "urn:milo:poc:padding-oracle",
                    "milo-security-poc",
                    "the padding oracle PoC server",
                    OpcUaServer.SDK_VERSION,
                    "",
                    DateTime.now()))
            .setCertificateManager(certificateManager)
            .setIdentityValidator(
                new CompositeValidator(AnonymousIdentityValidator.INSTANCE, usernameIdentityValidator))
            .setProductUri("urn:milo:poc:padding-oracle")
            .setLimits(new OpcUaServerConfigLimits() {})
            .build();

    OpcUaServer server =
        new OpcUaServer(
            serverConfig,
            transportProfile -> {
              if (transportProfile == TransportProfile.TCP_UASC_UABINARY) {
                return new OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build());
              } else {
                throw new RuntimeException("unexpected TransportProfile: " + transportProfile);
              }
            });

    return new Built(server, certificate);
  }

  private static Set<EndpointConfig> createEndpointConfigs(
      X509Certificate certificate, int port, String policyId) {
    Set<EndpointConfig> endpointConfigurations = new LinkedHashSet<>();

    UserTokenPolicy usernameRsa15Policy =
        new UserTokenPolicy(
            policyId, UserTokenType.UserName, null, null, SecurityPolicy.Basic128Rsa15.getUri());

    EndpointConfig.Builder builder =
        EndpointConfig.newBuilder()
            .setBindAddress("localhost")
            .setHostname("localhost")
            .setPath("/test")
            .setCertificate(certificate)
            .addTokenPolicies(OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS, usernameRsa15Policy)
            .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
            .setBindPort(port)
            .setSecurityPolicy(SecurityPolicy.None)
            .setSecurityMode(MessageSecurityMode.None);

    endpointConfigurations.add(builder.build());

    return endpointConfigurations;
  }
}
