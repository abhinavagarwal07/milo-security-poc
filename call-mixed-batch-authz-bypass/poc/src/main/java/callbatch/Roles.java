/*
 * the mixed-batch bypass PoC: shared role NodeIds.
 *
 * Every session is mapped (by the RoleMapper installed in PocServer) to at least the Operator
 * role. The "resetDevice" method additionally requires Call permission for Admin, which the
 * attacker (anonymous) never holds -- exactly the setup a real deployment uses to restrict a
 * dangerous operation to a privileged identity via UserRolePermissions/RolePermissionType.
 */
package callbatch;

import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;

public final class Roles {

  private Roles() {}

  public static final NodeId OPERATOR = new NodeId(0, "urn:callbatch:role:Operator");
  public static final NodeId ADMIN = new NodeId(0, "urn:callbatch:role:Admin");
}
