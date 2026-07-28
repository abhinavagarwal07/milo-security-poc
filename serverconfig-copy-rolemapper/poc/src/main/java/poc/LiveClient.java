/*
 * the RoleMapper-drop defect PoC: independent legitimate monitoring client.
 *
 * Models an ordinary HMI/SCADA display or historian client that has nothing to do with the
 * attack: it connects on its own, subscribes to PumpController/PumpFlow BEFORE any attack, and
 * simply keeps receiving the live feed for durationSeconds -- a separate JVM/TCP session from
 * both PocServer and AttackerClient. It never calls restartPump and never asks for anything
 * beyond Browse/Read, both of which every identity is entitled to in this deployment (Value
 * read is AccessLevel-gated, not RolePermissions-gated -- this client's access was never in
 * question). Its only role in this PoC is to be a stand-in for a real operator/monitoring
 * system and report, independently, whether the feed it was already receiving kept working.
 *
 * On vulnerable Milo the anonymous AttackerClient's Call succeeds mid-stream and this client's
 * feed visibly dies (notifications stop advancing, status flips Bad_NoCommunication). On fixed
 * Milo the Call is denied and this client's feed is completely undisturbed throughout.
 *
 * argv: [endpointUrl] [durationSeconds]
 *
 * Prints (epoch-ms timestamped so run.sh can correlate against AttackerClient's own ts=).
 * lastStatus is rendered as a single space-free token (Good | Bad_0x<hex>) specifically so
 * run.sh can parse these lines as plain whitespace-separated key=value pairs:
 *   LIVE_STARTED ts=<epochMs>
 *   LIVE_HEARTBEAT ts=<epochMs> tSec=<n> notifications=<N> lastGood=<bool> lastStatus=<tok> lastValue=<v>
 *   LIVE_SUMMARY ts=<epochMs> totalNotifications=<N> lastGood=<bool> lastStatus=<tok>
 */
package poc;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaMonitoredItem;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaSubscription;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;

public class LiveClient {

  public static void main(String[] args) throws Exception {
    String url = args.length > 0 ? args[0] : "opc.tcp://localhost:12686/poc";
    int durationSeconds = args.length > 1 ? Integer.parseInt(args[1]) : 12;

    OpcUaClient client = ClientUtil.connectAnonymous(url, "rolemapper-legit-monitor");
    try {
      NodeId objectId =
          ClientUtil.findChildByBrowseName(client, NodeIds.ObjectsFolder, "PumpController");
      NodeId flowId =
          objectId == null ? null : ClientUtil.findChildByBrowseName(client, objectId, "PumpFlow");
      if (flowId == null) {
        System.out.println("LIVE_ABORT reason=PumpFlow_not_found");
        return;
      }

      AtomicInteger notifications = new AtomicInteger(0);
      AtomicReference<String> lastStatus = new AtomicReference<>("none");
      AtomicBoolean lastGood = new AtomicBoolean(false);
      AtomicReference<Object> lastValue = new AtomicReference<>(null);

      OpcUaSubscription subscription = new OpcUaSubscription(client, 200.0);
      subscription.create();

      OpcUaMonitoredItem item = OpcUaMonitoredItem.newDataItem(flowId);
      item.setDataValueListener(
          (mi, dv) -> {
            notifications.incrementAndGet();
            StatusCode sc = dv.statusCode();
            lastStatus.set(compactStatus(sc));
            lastGood.set(sc != null && sc.isGood());
            lastValue.set(dv.value() == null ? null : dv.value().getValue());
          });
      subscription.addMonitoredItems(List.of(item));
      subscription.createMonitoredItems();

      System.out.println("LIVE_STARTED ts=" + System.currentTimeMillis());
      System.out.flush();

      for (int t = 1; t <= durationSeconds; t++) {
        Thread.sleep(1000);
        System.out.println(
            "LIVE_HEARTBEAT ts="
                + System.currentTimeMillis()
                + " tSec="
                + t
                + " notifications="
                + notifications.get()
                + " lastGood="
                + lastGood.get()
                + " lastStatus="
                + lastStatus.get()
                + " lastValue="
                + lastValue.get());
        System.out.flush();
      }

      System.out.println(
          "LIVE_SUMMARY ts="
              + System.currentTimeMillis()
              + " totalNotifications="
              + notifications.get()
              + " lastGood="
              + lastGood.get()
              + " lastStatus="
              + lastStatus.get());
      System.out.flush();

      try {
        subscription.delete();
      } catch (Exception ignored) {
      }
    } finally {
      client.disconnect();
    }
  }

  /** Render a StatusCode as one whitespace-free token -- "Good" or "Bad_0x<hex>". */
  private static String compactStatus(StatusCode sc) {
    if (sc == null) {
      return "none";
    }
    return sc.isGood() ? "Good" : ("Bad_0x" + Long.toHexString(sc.getValue()));
  }
}
