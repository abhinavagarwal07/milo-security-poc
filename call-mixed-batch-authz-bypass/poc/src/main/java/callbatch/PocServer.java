/*
 * the mixed-batch bypass PoC: server harness.
 *
 * Boots Milo's public server SDK entry point, org.eclipse.milo.examples.server.ExampleServer
 * (reused directly via its Consumer<OpcUaServerConfigBuilder> constructor -- not an
 * internal/test-only class), with:
 *   - a RoleMapper granting the Operator role to every session (anonymous included), and
 *     ADDITIONALLY the Admin role to the "admin" username identity. ExampleServer's own
 *     built-in UsernameIdentityValidator already accepts admin/password2 -- unrelated to this
 *     bug, reused purely as the "legitimately authorized administrator" identity for the
 *     calibration control (an Admin logging in and calling the protected method directly, to
 *     establish the method's real, intended effect independent of the bypass);
 *   - the PocNamespace RBAC-protected object/method model (see PocNamespace.java).
 *
 * SecurityPolicy.None only, to keep the PoC focused purely on the Call-service authorization
 * bypass, independent of any transport-security feature.
 *
 * Usage: java -jar call-batch-poc.jar PocServer [port] [countersFile]
 */
package callbatch;

import java.util.List;
import org.eclipse.milo.examples.server.ExampleServer;
import org.eclipse.milo.opcua.sdk.server.RoleMapper;
import org.eclipse.milo.opcua.sdk.server.identity.Identity;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;

public class PocServer {

  public static void main(String[] args) throws Exception {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : 12686;
    String countersFile =
        args.length > 1 ? args[1] : "/tmp/call-batch-side-effects.txt";

    RoleMapper roleMapper =
        new RoleMapper() {
          @Override
          public List<NodeId> getRoleIds(Identity identity) {
            if (identity instanceof Identity.UsernameIdentity ui
                && "admin".equals(ui.getUsername())) {
              // The one legitimately-authorized administrative identity, used ONLY for the
              // calibration control (never by the attacker).
              return List.of(Roles.OPERATOR, Roles.ADMIN);
            }
            // Every other session -- anonymous or otherwise -- is mapped to Operator only.
            return List.of(Roles.OPERATOR);
          }
        };

    ExampleServer exampleServer = new ExampleServer(port, b -> b.setRoleMapper(roleMapper));

    PocNamespace pocNamespace = new PocNamespace(exampleServer.getServer(), countersFile);
    pocNamespace.startup();

    exampleServer.startup().get();

    long pid = ProcessHandle.current().pid();
    System.out.println(
        "POC_SERVER_READY pid=" + pid + " port=" + port + " countersFile=" + countersFile);
    System.out.flush();

    Thread.currentThread().join();
  }
}
