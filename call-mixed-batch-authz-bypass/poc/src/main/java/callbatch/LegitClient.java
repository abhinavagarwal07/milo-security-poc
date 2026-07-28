/*
 * the mixed-batch bypass PoC: an independent, third "legitimate client" -- the live victim.
 *
 * A genuine, unmodified milo-sdk-client client. Connects ANONYMOUSLY (an ordinary monitoring
 * session -- NOT the attacker's session, and NOT the admin/calibration identity used elsewhere
 * in this PoC) to a distinct session on the same server, Browses to discover
 * Plant/SensorFeed/Value, opens a real OpcUaSubscription with a monitored item on that node, and
 * logs every DataChangeNotification it receives to stdout.
 *
 * Purpose: give the mixed-batch Call authorization bypass (the mixed-batch bypass) a genuinely
 * independent, third-party observable effect -- rather than only a synthetic server-side
 * invocation counter -- so the story is: "the server reported denial to the attacker, but the
 * forbidden command had already disrupted another connected client."
 *
 * Usage: java -cp <jar> callbatch.LegitClient <url> <durationSeconds>
 *
 * Runs for the given duration, disconnects, and prints a LEGIT_SUMMARY line. Intended to be
 * launched in the background (stdout redirected to a log file) by run.sh, so the log can be
 * tailed/diffed before vs. after the attacker's mixed-batch phases.
 */
package callbatch;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaMonitoredItem;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaSubscription;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExpandedNodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;

public class LegitClient {

  private static final AtomicInteger GOOD_TICKS = new AtomicInteger(0);
  private static final AtomicInteger BAD_TICKS = new AtomicInteger(0);
  private static volatile StatusCode lastStatus = StatusCode.GOOD;

  public static void main(String[] args) throws Exception {
    String url = args.length > 0 ? args[0] : "opc.tcp://localhost:12686/milo";
    int durationSeconds = args.length > 1 ? Integer.parseInt(args[1]) : 10;

    System.out.println(
        "LEGIT_CLIENT starting url=" + url + " durationSeconds=" + durationSeconds
            + " identity=anonymous (independent third victim session)");
    System.out.flush();

    OpcUaClient client = createClient(url);
    client.connect();
    System.out.println("LEGIT_CLIENT connected (anonymous, SecurityPolicy.None)");

    NodeId plantId =
        browseChild(client, org.eclipse.milo.opcua.stack.core.NodeIds.ObjectsFolder, "Plant");
    NodeId sensorFeedId = browseChild(client, plantId, "SensorFeed");
    NodeId valueId = browseChild(client, sensorFeedId, "Value");
    System.out.println("LEGIT_CLIENT discovered Plant/SensorFeed/Value=" + valueId);

    OpcUaSubscription subscription = new OpcUaSubscription(client, 200.0);
    subscription.create();

    OpcUaMonitoredItem item = OpcUaMonitoredItem.newDataItem(valueId);
    item.setSamplingInterval(200.0);
    item.setDataValueListener(LegitClient::onDataReceived);
    subscription.addMonitoredItem(item);
    subscription.createMonitoredItems();

    long endAt = System.currentTimeMillis() + durationSeconds * 1000L;
    while (System.currentTimeMillis() < endAt) {
      Thread.sleep(200);
    }

    try {
      subscription.delete();
    } catch (Exception ignored) {
    }
    try {
      client.disconnectAsync().get(3, java.util.concurrent.TimeUnit.SECONDS);
    } catch (Exception ignored) {
    }

    System.out.println(
        "LEGIT_SUMMARY ts="
            + System.currentTimeMillis()
            + " goodTicks="
            + GOOD_TICKS.get()
            + " badTicks="
            + BAD_TICKS.get()
            + " lastStatus="
            + lastStatus);
    System.out.flush();
    Runtime.getRuntime().halt(0);
  }

  private static void onDataReceived(OpcUaMonitoredItem item, DataValue value) {
    StatusCode sc = value.getStatusCode() != null ? value.getStatusCode() : StatusCode.GOOD;
    lastStatus = sc;
    int good = GOOD_TICKS.get();
    int bad = BAD_TICKS.get();
    if (sc.isGood()) {
      good = GOOD_TICKS.incrementAndGet();
    } else {
      bad = BAD_TICKS.incrementAndGet();
    }
    System.out.println(
        "LEGIT_TICK ts="
            + System.currentTimeMillis()
            + " value="
            + value.getValue().getValue()
            + " statusCode="
            + sc
            + " goodTicks="
            + good
            + " badTicks="
            + bad);
    System.out.flush();
  }

  /** Browse {@code parent} and return the NodeId of its child with the given BrowseName. */
  private static NodeId browseChild(OpcUaClient client, NodeId parent, String browseName)
      throws Exception {
    List<ReferenceDescription> refs = client.getAddressSpace().browse(parent);
    for (ReferenceDescription ref : refs) {
      QualifiedName bn = ref.getBrowseName();
      if (bn != null && browseName.equals(bn.name())) {
        ExpandedNodeId xni = ref.getNodeId();
        return client.getAddressSpace().toNodeId(xni);
      }
    }
    throw new IllegalStateException(
        "could not find child '" + browseName + "' under " + parent + " via Browse");
  }

  /** Build an ordinary anonymous client, distinct from the attacker's and the admin's sessions. */
  private static OpcUaClient createClient(String url) throws Exception {
    Predicate<EndpointDescription> predicate =
        e ->
            SecurityPolicy.None.getUri().equals(e.getSecurityPolicyUri())
                && java.util.stream.Stream.of(
                        java.util.Objects.requireNonNullElse(
                            e.getUserIdentityTokens(),
                            new org.eclipse.milo.opcua.stack.core.types.structured
                                .UserTokenPolicy[0]))
                    .anyMatch(p -> p.getTokenType() == UserTokenType.Anonymous);

    return OpcUaClient.create(
        url,
        endpoints -> {
          Optional<EndpointDescription> selected = endpoints.stream().filter(predicate).findFirst();
          return selected;
        },
        transportConfig -> {},
        configBuilder -> {
          configBuilder.setIdentityProvider(new AnonymousProvider());
          configBuilder.setRequestTimeout(Unsigned.uint(5_000));
        });
  }
}
