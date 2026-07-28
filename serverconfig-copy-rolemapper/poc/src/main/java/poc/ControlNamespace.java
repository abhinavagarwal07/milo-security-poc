/*
 * the RoleMapper-drop defect PoC: the RBAC-protected address space.
 *
 * Exposes a "PumpController" object modeling a small live device driver:
 *   - "PumpFlow"        -- a Variable that a background thread ticks upward every 300ms while
 *                          the (simulated) pump is running, Good status. This is the live feed
 *                          an independent monitoring client (LiveClient) subscribes to.
 *   - "InvocationCount" -- a counter incremented from inside restartPump's method body, kept as
 *                          server-side ground truth that the privileged operation actually ran.
 *   - "restartPump"     -- a method modeling a privileged device-control operation. Its
 *                          (User)RolePermissions grant Call ONLY to AdminRole; ObserverRole --
 *                          the role this deployment's RoleMapper grants every anonymous client
 *                          -- gets Browse only, never Call. Invoking it cancels the PumpFlow
 *                          ticker and flips PumpFlow to Bad_NoCommunication: a real, externally
 *                          observable disruption to whatever is watching PumpFlow, not just a
 *                          local counter increment. There is no Observer-reachable "start"
 *                          method, so the disruption is permanent until the process restarts --
 *                          mirroring a real device-control "stop"/"fault" operation.
 *
 * Both PumpFlow and InvocationCount are readable by BOTH roles: Value read/write is gated by
 * AccessLevel, not RolePermissions -- Milo's DefaultAccessController does not gate Value
 * reads/writes by RolePermissions at all, only Browse, Call, RolePermissions/Historizing
 * attribute reads, and AddNodes/DeleteNodes do. Exposing them this way lets both the attacker
 * and an independent legitimate monitoring client observe the side effect/disruption without
 * needing any additional privileged operation -- reading the proof does not itself exercise
 * the Call path under test.
 */
package poc;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.eclipse.milo.opcua.sdk.core.AccessLevel;
import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.server.Lifecycle;
import org.eclipse.milo.opcua.sdk.server.ManagedNamespaceWithLifecycle;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.items.DataItem;
import org.eclipse.milo.opcua.sdk.server.items.MonitoredItem;
import org.eclipse.milo.opcua.sdk.server.methods.AbstractMethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaObjectNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.sdk.server.util.SubscriptionModel;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.Argument;
import org.eclipse.milo.opcua.stack.core.types.structured.PermissionType;
import org.eclipse.milo.opcua.stack.core.types.structured.RolePermissionType;

public class ControlNamespace extends ManagedNamespaceWithLifecycle {

  public static final String NAMESPACE_URI = "urn:rolemapper:poc";

  /** Privileged role required to Call restartPump. The RoleMapper never grants this to anon. */
  public static final NodeId ADMIN_ROLE = new NodeId(1, "AdminRole");

  /** The only role the deployment's RoleMapper grants anonymous clients. */
  public static final NodeId OBSERVER_ROLE = new NodeId(1, "ObserverRole");

  private final SubscriptionModel subscriptionModel;
  private final AtomicInteger restartPumpInvocations = new AtomicInteger(0);

  // ---- live PumpFlow ticker -- what the independent LiveClient subscribes to ----
  private final ScheduledExecutorService pumpScheduler =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread t = new Thread(r, "pump-flow-driver");
            t.setDaemon(true);
            return t;
          });
  private volatile ScheduledFuture<?> pumpTask;
  private final AtomicBoolean pumpRunning = new AtomicBoolean(true);
  private final AtomicInteger pumpFlowValue = new AtomicInteger(0);

  private volatile UaVariableNode invocationCountNode;
  private volatile UaVariableNode pumpFlowNode;
  private volatile NodeId controllerObjectId;
  private volatile NodeId restartPumpMethodId;

  public ControlNamespace(OpcUaServer server) {
    super(server, NAMESPACE_URI);
    subscriptionModel = new SubscriptionModel(server, this);
    getLifecycleManager().addLifecycle(subscriptionModel);
    getLifecycleManager()
        .addLifecycle(
            new Lifecycle() {
              @Override
              public void startup() {
                addNodes();
                startPumpTicker();
              }

              @Override
              public void shutdown() {
                pumpScheduler.shutdownNow();
              }
            });
  }

  public NodeId getControllerObjectId() {
    return controllerObjectId;
  }

  public NodeId getRestartPumpMethodId() {
    return restartPumpMethodId;
  }

  /** The ground truth: how many times the privileged method body actually ran. */
  public int getRestartPumpInvocations() {
    return restartPumpInvocations.get();
  }

  private void addNodes() {
    // Browse+Read granted to both roles; Call granted to AdminRole only. An Observer-role
    // session (which is what every anonymous client is mapped to) can see and browse the
    // method but must never be able to invoke it.
    RolePermissionType[] browseReadBoth =
        new RolePermissionType[] {
          new RolePermissionType(
              OBSERVER_ROLE,
              PermissionType.of(PermissionType.Field.Browse, PermissionType.Field.Read)),
          new RolePermissionType(
              ADMIN_ROLE,
              PermissionType.of(PermissionType.Field.Browse, PermissionType.Field.Read))
        };
    RolePermissionType[] callAdminOnly =
        new RolePermissionType[] {
          new RolePermissionType(OBSERVER_ROLE, PermissionType.of(PermissionType.Field.Browse)),
          new RolePermissionType(
              ADMIN_ROLE,
              PermissionType.of(PermissionType.Field.Browse, PermissionType.Field.Call))
        };

    NodeId objId = newNodeId("PumpController");
    UaObjectNode controller =
        UaObjectNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(objId);
              b.setBrowseName(newQualifiedName("PumpController"));
              b.setDisplayName(LocalizedText.english("PumpController"));
              b.addReference(
                  new Reference(
                      objId,
                      NodeIds.HasComponent,
                      NodeIds.ObjectsFolder.expanded(),
                      Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    controller.setRolePermissions(browseReadBoth);
    controller.setUserRolePermissions(browseReadBoth);
    controllerObjectId = objId;

    // Live feed: an independent monitoring client subscribes to this. It ticks upward every
    // 300ms with Good status while the pump is running, and is what restartPump disrupts.
    NodeId flowId = newNodeId("PumpController/PumpFlow");
    pumpFlowNode =
        UaVariableNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(flowId);
              b.setBrowseName(newQualifiedName("PumpFlow"));
              b.setDisplayName(LocalizedText.english("PumpFlow"));
              b.setDataType(NodeIds.Int32);
              b.setAccessLevel(AccessLevel.READ_ONLY);
              b.setUserAccessLevel(AccessLevel.READ_ONLY);
              b.setValue(new DataValue(new Variant(0)));
              b.addReference(
                  new Reference(
                      flowId, NodeIds.HasComponent, objId.expanded(), Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    pumpFlowNode.setRolePermissions(browseReadBoth);
    pumpFlowNode.setUserRolePermissions(browseReadBoth);
    controller.addReference(
        new Reference(objId, NodeIds.HasComponent, flowId.expanded(), Reference.Direction.FORWARD));

    // Observable side-effect counter -- server-side ground truth that restartPump's body ran.
    NodeId counterId = newNodeId("PumpController/InvocationCount");
    invocationCountNode =
        UaVariableNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(counterId);
              b.setBrowseName(newQualifiedName("InvocationCount"));
              b.setDisplayName(LocalizedText.english("InvocationCount"));
              b.setDataType(NodeIds.Int32);
              b.setAccessLevel(AccessLevel.READ_ONLY);
              b.setUserAccessLevel(AccessLevel.READ_ONLY);
              b.setValue(new DataValue(new Variant(0)));
              b.addReference(
                  new Reference(
                      counterId, NodeIds.HasComponent, objId.expanded(), Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    invocationCountNode.setRolePermissions(browseReadBoth);
    invocationCountNode.setUserRolePermissions(browseReadBoth);
    controller.addReference(
        new Reference(objId, NodeIds.HasComponent, counterId.expanded(), Reference.Direction.FORWARD));

    NodeId methodId = newNodeId("PumpController/restartPump");
    UaMethodNode restartPump =
        UaMethodNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(methodId);
              b.setBrowseName(newQualifiedName("restartPump"));
              b.setDisplayName(LocalizedText.english("restartPump"));
              b.setExecutable(true);
              b.setUserExecutable(true);
              b.addReference(
                  new Reference(
                      methodId, NodeIds.HasComponent, objId.expanded(), Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    restartPump.setInvocationHandler(
        new AbstractMethodInvocationHandler(restartPump) {
          @Override
          public Argument[] getInputArguments() {
            return new Argument[0];
          }

          @Override
          public Argument[] getOutputArguments() {
            return new Argument[0];
          }

          @Override
          protected Variant[] invoke(InvocationContext invocationContext, Variant[] inputValues) {
            int n = restartPumpInvocations.incrementAndGet();
            invocationCountNode.setValue(new DataValue(new Variant(n)));

            // The real disruption: stop the live feed and flip it Bad. Anything -- attacker or
            // an unrelated legitimate client -- currently subscribed to PumpFlow sees this.
            boolean wasRunning = pumpRunning.compareAndSet(true, false);
            if (pumpTask != null) {
              pumpTask.cancel(false);
            }
            pumpFlowNode.setValue(
                new DataValue(
                    new Variant(0),
                    new StatusCode(StatusCodes.Bad_NoCommunication),
                    DateTime.now()));

            System.out.println(
                "POC_SIDE_EFFECT restartPump EXECUTED invocationCount=" + n
                    + " pumpWasRunning=" + wasRunning
                    + " pumpFlowNowBad=true"
                    + " (the privileged method body actually ran on the server and stopped"
                    + " the live PumpFlow feed)");
            System.out.flush();
            return new Variant[0];
          }
        });
    restartPump.setRolePermissions(callAdminOnly);
    restartPump.setUserRolePermissions(callAdminOnly);
    controller.addReference(
        new Reference(
            objId, NodeIds.HasComponent, methodId.expanded(), Reference.Direction.FORWARD));
    restartPumpMethodId = methodId;
  }

  private void startPumpTicker() {
    pumpTask =
        pumpScheduler.scheduleAtFixedRate(
            () -> {
              if (!pumpRunning.get()) {
                return;
              }
              int v = pumpFlowValue.incrementAndGet();
              pumpFlowNode.setValue(new DataValue(new Variant(v)));
            },
            0,
            300,
            TimeUnit.MILLISECONDS);
  }

  @Override
  public void onDataItemsCreated(List<DataItem> dataItems) {
    subscriptionModel.onDataItemsCreated(dataItems);
  }

  @Override
  public void onDataItemsModified(List<DataItem> dataItems) {
    subscriptionModel.onDataItemsModified(dataItems);
  }

  @Override
  public void onDataItemsDeleted(List<DataItem> dataItems) {
    subscriptionModel.onDataItemsDeleted(dataItems);
  }

  @Override
  public void onMonitoringModeChanged(List<MonitoredItem> monitoredItems) {
    subscriptionModel.onMonitoringModeChanged(monitoredItems);
  }
}
