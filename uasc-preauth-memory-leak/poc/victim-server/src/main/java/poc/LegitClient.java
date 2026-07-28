/*
 * UASC pre-authentication memory-leak PoC: legitimate client probe.
 *
 * Performs a full, honest OPC UA session against the victim server: GetEndpoints,
 * OpenSecureChannel (SecurityPolicy.None / Anonymous), CreateSession/ActivateSession,
 * then reads Server_ServerStatus_State. Prints a single machine-parseable line:
 *
 *   LEGIT_CLIENT_RESULT=SUCCESS ...   (server healthy, request served)
 *   LEGIT_CLIENT_RESULT=FAILURE ...   (server denied service / unreachable / hung)
 *
 * Run before/during/after the attack to demonstrate availability impact (or its absence).
 */
package poc;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;

public class LegitClient {

  public static void main(String[] args) {
    String url = args.length > 0 ? args[0] : "opc.tcp://127.0.0.1:12686/milo";
    long t0 = System.currentTimeMillis();

    // Hard watchdog: if a memory-exhausted server hangs the handshake instead of
    // failing it outright, record a denial rather than blocking forever.
    int watchdogSec = Integer.getInteger("legit.timeout.sec", 60);
    Thread watchdog =
        new Thread(
            () -> {
              try {
                Thread.sleep(watchdogSec * 1000L);
                System.out.printf(
                    "LEGIT_CLIENT_RESULT=FAILURE url=%s error=WATCHDOG_TIMEOUT_%ds"
                        + " (server unresponsive) elapsedMs=%d%n",
                    url, watchdogSec, System.currentTimeMillis() - t0);
                System.out.flush();
                Runtime.getRuntime().halt(1);
              } catch (InterruptedException ignored) {
              }
            },
            "legit-watchdog");
    watchdog.setDaemon(true);
    watchdog.start();

    OpcUaClient client = null;
    try {
      client = OpcUaClient.create(url);
      client.connect();

      UaVariableNode node =
          client.getAddressSpace().getVariableNode(NodeIds.Server_ServerStatus_State);
      DataValue v = node.readValue();

      System.out.printf(
          "LEGIT_CLIENT_RESULT=SUCCESS url=%s state=%s elapsedMs=%d%n",
          url, String.valueOf(v.value().value()), System.currentTimeMillis() - t0);
      System.out.flush();
      client.disconnect();
      Runtime.getRuntime().halt(0);
    } catch (Throwable e) {
      String msg = e.getMessage();
      if (msg != null && msg.length() > 200) {
        msg = msg.substring(0, 200);
      }
      System.out.printf(
          "LEGIT_CLIENT_RESULT=FAILURE url=%s error=%s: %s elapsedMs=%d%n",
          url, e.getClass().getName(), msg, System.currentTimeMillis() - t0);
      System.out.flush();
      Runtime.getRuntime().halt(1);
    }
  }
}
