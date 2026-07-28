package poc;

import java.util.List;
import java.util.Optional;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.identity.UsernameProvider;
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import poc.common.Args;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Process 2 of 5: the legitimate victim. Authenticates through the recording relay ({@link
 * RelayMain}) using the Basic128Rsa15 username policy, does one harmless read, disconnects.
 *
 * <p>This process holds the password (it is the legitimate user) -- that is expected and correct.
 * It never talks to {@link AttackerMain} directly or shares any state with it; the only thing
 * that crosses from this side of the PoC to the attacker side is the ciphertext {@link RelayMain}
 * extracts from the wire bytes it records.
 */
public class VictimMain {

  private static final Logger LOGGER = LoggerFactory.getLogger(VictimMain.class);

  public static void main(String[] args) throws Exception {
    Args a = Args.parse(args);
    String endpointUrl = a.require("endpoint-url");
    String username = a.require("username");
    String password = a.require("password");
    String policyId = a.get("policy-id", "username_rsa15");

    LOGGER.info("[victim] connecting through relay at {}", endpointUrl);

    OpcUaClient victim =
        OpcUaClient.create(
            endpointUrl,
            endpoints -> {
              Optional<EndpointDescription> chosen =
                  endpoints.stream()
                      .filter(ep -> SecurityPolicy.None.getUri().equals(ep.getSecurityPolicyUri()))
                      .findFirst();
              return chosen.map(ep -> rewriteEndpointUrl(ep, endpointUrl));
            },
            tcfg -> {},
            ccfg ->
                ccfg.setIdentityProvider(
                        new UsernameProvider(
                            username,
                            password,
                            new CertificateValidator.InsecureCertificateValidator(),
                            policies -> {
                              for (UserTokenPolicy p : policies) {
                                if (policyId.equals(p.getPolicyId())) {
                                  return p;
                                }
                              }
                              return policies.get(0);
                            }))
                    .setRequestTimeout(org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger.valueOf(15_000)));

    victim.connect();
    try {
      victim.readValues(0.0, TimestampsToReturn.Neither, List.of(NodeId.parse("i=2259")));
      LOGGER.info("[victim] authenticated and completed one read");
    } catch (Exception ignore) {
      // Not essential; the ActivateSession has already gone out over the wire and been recorded.
    }
    try {
      victim.disconnectAsync().get(5, java.util.concurrent.TimeUnit.SECONDS);
    } catch (Exception ignore) {
    }
    System.out.println("VICTIM_DONE");
  }

  private static EndpointDescription rewriteEndpointUrl(EndpointDescription ep, String url) {
    return new EndpointDescription(
        url,
        ep.getServer(),
        ep.getServerCertificate(),
        ep.getSecurityMode(),
        ep.getSecurityPolicyUri(),
        ep.getUserIdentityTokens(),
        ep.getTransportProfileUri(),
        ep.getSecurityLevel());
  }
}
