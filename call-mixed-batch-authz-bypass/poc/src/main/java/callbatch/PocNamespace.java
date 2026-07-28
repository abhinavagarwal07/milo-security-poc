/*
 * the mixed-batch bypass PoC: namespace modelling a realistic RBAC-protected industrial deployment.
 *
 * Exposes, under Plant/Device:
 *  - readStatus()   : Operator AND Admin may Call. Benign; used as the "carrier" (authorized)
 *                     method placed alongside the denied one in the mixed CallRequest batch.
 *  - resetDevice()  : Operator may Browse (can see/discover the method exists -- realistic
 *                     address-space disclosure) but Call is granted to Admin ONLY. This is the
 *                     denied/integrity target: an Operator-level (or anonymous) session must
 *                     never be able to trigger it.
 *
 * All authorization here is enforced purely through UserRolePermissions (RolePermissionType /
 * PermissionType.Field.Call), i.e. the Roles-and-Permissions (AccessController) subsystem that
 * DefaultMethodServiceSet.call() is supposed to gate Call dispatch through -- exactly the
 * mechanism the mixed-batch bypass defeats for mixed batches.
 *
 * Invocation counters are written, after every method invocation, to a well-known file so the
 * orchestrating shell script (run.sh) can read server-side ground truth independent of whatever
 * status code the client ends up observing on the wire (which, on the vulnerable build, may not
 * arrive at all for a mixed batch -- see Attacker.java).
 */
package callbatch;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.eclipse.milo.opcua.sdk.core.AccessLevel;
import org.eclipse.milo.opcua.sdk.core.Reference;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PocNamespace extends ManagedNamespaceWithLifecycle {

  public static final String NAMESPACE_URI = "urn:callbatch:poc";

  private static final Logger LOG = LoggerFactory.getLogger(PocNamespace.class);

  private final SubscriptionModel subscriptionModel;
  private final String countersFile;

  private final AtomicInteger statusInvocations = new AtomicInteger(0);
  private final AtomicInteger resetInvocations = new AtomicInteger(0);
  private final AtomicBoolean deviceReset = new AtomicBoolean(false);

  // -- SensorFeed subsystem: a live, ticking third-party observable, added so the mixed-batch
  // bypass has a genuine, independently-witnessed effect beyond a synthetic invocation counter
  // (see LegitClient.java). "stopSensorFeed" has the identical RBAC shape as "resetDevice"
  // (Operator: Browse only; Admin: Browse + Call) -- it is the SAME kind of denied/integrity
  // target, just wired to a real, observable side effect instead of a boolean flag.
  private final ScheduledExecutorService scheduler =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread t = new Thread(r, "sensor-feed-driver");
            t.setDaemon(true);
            return t;
          });
  private volatile ScheduledFuture<?> feedTask;
  private final AtomicBoolean feedRunning = new AtomicBoolean(true);
  private final AtomicInteger stopFeedInvocations = new AtomicInteger(0);
  private UaVariableNode sensorValueNode;

  public PocNamespace(OpcUaServer server, String countersFile) {
    super(server, NAMESPACE_URI);
    this.countersFile = countersFile;

    subscriptionModel = new SubscriptionModel(server, this);
    getLifecycleManager().addLifecycle(subscriptionModel);
    getLifecycleManager().addStartupTask(this::createAndAddNodes);
    getLifecycleManager()
        .addLifecycle(
            new org.eclipse.milo.opcua.sdk.server.Lifecycle() {
              @Override
              public void startup() {
                startSensorFeed();
              }

              @Override
              public void shutdown() {
                feedRunning.set(false);
                if (feedTask != null) {
                  feedTask.cancel(false);
                }
                scheduler.shutdownNow();
              }
            });
  }

  private void createAndAddNodes() {
    NodeId plantId = newNodeId("Plant");
    UaObjectNode plant =
        UaObjectNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(plantId);
              b.setBrowseName(newQualifiedName("Plant"));
              b.setDisplayName(LocalizedText.english("Plant"));
              b.addReference(
                  new Reference(
                      b.getNodeId(),
                      NodeIds.Organizes,
                      NodeIds.ObjectsFolder.expanded(),
                      Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    plant.setUserRolePermissions(operatorAndAdmin(PermissionType.Field.Browse));

    addDevice(plant);
    addSensorFeed(plant);
    writeCounters();
  }

  private void addDevice(UaObjectNode plant) {
    NodeId deviceId = newNodeId("Plant/Device");
    UaObjectNode device =
        UaObjectNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(deviceId);
              b.setBrowseName(newQualifiedName("Device"));
              b.setDisplayName(LocalizedText.english("Device"));
              b.addReference(
                  new Reference(
                      b.getNodeId(),
                      NodeIds.HasComponent,
                      plant.getNodeId().expanded(),
                      Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    device.setUserRolePermissions(
        operatorAndAdmin(PermissionType.Field.Browse, PermissionType.Field.Call));

    UaMethodNode readStatus =
        buildMethod(
            deviceId,
            "readStatus",
            () -> {
              int n = statusInvocations.incrementAndGet();
              LOG.info("SIDE_EFFECT readStatus invoked count={}", n);
              writeCounters();
            });
    readStatus.setUserRolePermissions(
        operatorAndAdmin(PermissionType.Field.Browse, PermissionType.Field.Call));

    UaMethodNode resetDevice =
        buildMethod(
            deviceId,
            "resetDevice",
            () -> {
              deviceReset.set(true);
              int n = resetInvocations.incrementAndGet();
              LOG.info("SIDE_EFFECT resetDevice invoked count={} deviceReset=true", n);
              writeCounters();
            });
    // Operator can BROWSE/see this method (realistic address-space disclosure) but is NOT
    // granted Call -- only Admin is. This is the DENIED target: Operator holds no Call
    // permission on it at all.
    resetDevice.setUserRolePermissions(
        new RolePermissionType[] {
          new RolePermissionType(Roles.OPERATOR, PermissionType.of(PermissionType.Field.Browse)),
          new RolePermissionType(
              Roles.ADMIN,
              PermissionType.of(PermissionType.Field.Browse, PermissionType.Field.Call))
        });
  }

  /** Builds a method under {@code Plant/Device/<name>} (legacy call site, kept unchanged). */
  private UaMethodNode buildMethod(NodeId parentId, String name, Runnable sideEffect) {
    return buildMethodAt(parentId, "Plant/Device/" + name, name, sideEffect);
  }

  /** Builds a method under an arbitrary parent path, identified by its full NodeId path suffix. */
  private UaMethodNode buildMethodAt(
      NodeId parentId, String nodeIdPath, String name, Runnable sideEffect) {
    return UaMethodNode.build(
        getNodeContext(),
        b -> {
          b.setNodeId(newNodeId(nodeIdPath));
          b.setBrowseName(newQualifiedName(name));
          b.setDisplayName(LocalizedText.english(name));
          b.addReference(
              new Reference(
                  b.getNodeId(),
                  NodeIds.HasComponent,
                  parentId.expanded(),
                  Reference.Direction.INVERSE));
          UaMethodNode node = b.buildAndAdd();
          node.setInvocationHandler(
              new AbstractMethodInvocationHandler(node) {
                @Override
                public Argument[] getInputArguments() {
                  return new Argument[0];
                }

                @Override
                public Argument[] getOutputArguments() {
                  return new Argument[0];
                }

                @Override
                protected Variant[] invoke(
                    InvocationContext invocationContext, Variant[] inputValues) {
                  sideEffect.run();
                  return new Variant[0];
                }
              });
          return node;
        });
  }

  /**
   * Adds a second, independent subsystem under Plant: a live "SensorFeed" that ticks a Double
   * value every 200ms (Browse granted to Operator+Admin, read-only) and an Admin-only
   * "stopSensorFeed" method (identical RBAC shape to resetDevice -- Operator can Browse/see it,
   * but Call is Admin-only) whose invocation permanently kills the ticking (no restart is
   * exposed) and forces the value node's DataValue to Bad_NoCommunication. This gives the
   * mixed-batch bypass a genuinely observable effect on a third, independent client subscribed
   * to Plant/SensorFeed/Value (see LegitClient.java), rather than only a synthetic counter.
   */
  private void addSensorFeed(UaObjectNode plant) {
    NodeId feedId = newNodeId("Plant/SensorFeed");
    UaObjectNode sensorFeed =
        UaObjectNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(feedId);
              b.setBrowseName(newQualifiedName("SensorFeed"));
              b.setDisplayName(LocalizedText.english("SensorFeed"));
              b.addReference(
                  new Reference(
                      b.getNodeId(),
                      NodeIds.HasComponent,
                      plant.getNodeId().expanded(),
                      Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    sensorFeed.setUserRolePermissions(
        operatorAndAdmin(PermissionType.Field.Browse, PermissionType.Field.Call));

    NodeId valueId = newNodeId("Plant/SensorFeed/Value");
    sensorValueNode =
        UaVariableNode.build(
            getNodeContext(),
            b -> {
              b.setNodeId(valueId);
              b.setAccessLevel(AccessLevel.toValue(AccessLevel.READ_ONLY));
              b.setUserAccessLevel(AccessLevel.toValue(AccessLevel.READ_ONLY));
              b.setBrowseName(newQualifiedName("Value"));
              b.setDisplayName(LocalizedText.english("Value"));
              b.setDataType(NodeIds.Double);
              b.setTypeDefinition(NodeIds.BaseDataVariableType);
              b.addReference(
                  new Reference(
                      b.getNodeId(),
                      NodeIds.HasComponent,
                      feedId.expanded(),
                      Reference.Direction.INVERSE));
              return b.buildAndAdd();
            });
    sensorValueNode.setUserRolePermissions(operatorAndAdmin(PermissionType.Field.Browse));
    sensorValueNode.setValue(new DataValue(new Variant(0.0)));

    UaMethodNode stopSensorFeed =
        buildMethodAt(
            feedId,
            "Plant/SensorFeed/stopSensorFeed",
            "stopSensorFeed",
            () -> {
              feedRunning.set(false);
              if (feedTask != null) {
                feedTask.cancel(false);
              }
              int n = stopFeedInvocations.incrementAndGet();
              sensorValueNode.setValue(
                  new DataValue(
                      Variant.NULL_VALUE,
                      new StatusCode(StatusCodes.Bad_NoCommunication),
                      DateTime.now()));
              LOG.info("SIDE_EFFECT stopSensorFeed invoked count={} feedRunning=false", n);
              writeCounters();
            });
    // Identical RBAC shape to resetDevice: Operator may Browse/see it, Call is Admin-only.
    stopSensorFeed.setUserRolePermissions(
        new RolePermissionType[] {
          new RolePermissionType(Roles.OPERATOR, PermissionType.of(PermissionType.Field.Browse)),
          new RolePermissionType(
              Roles.ADMIN,
              PermissionType.of(PermissionType.Field.Browse, PermissionType.Field.Call))
        });
  }

  /** Starts the SensorFeed ticking, updating {@link #sensorValueNode} every 200ms. */
  private void startSensorFeed() {
    feedTask =
        scheduler.scheduleAtFixedRate(
            () -> {
              if (!feedRunning.get()) {
                return;
              }
              double value = 20.0 + 5.0 * Math.sin(System.currentTimeMillis() / 2000.0);
              sensorValueNode.setValue(new DataValue(new Variant(value)));
            },
            0,
            200,
            TimeUnit.MILLISECONDS);
  }

  /**
   * Write cumulative invocation counters to a well-known, per-run file, as an authoritative,
   * easily-polled/grep-able alternative to scraping stdout -- and as the ONLY ground truth that
   * matters for this PoC's verdicts, since the client-visible wire outcome for a mixed batch on
   * the vulnerable build may be an exception/timeout rather than a clean CallResponse (see
   * Attacker.java).
   */
  private void writeCounters() {
    try {
      String content =
          "readStatus="
              + statusInvocations.get()
              + " resetDevice="
              + resetInvocations.get()
              + " deviceReset="
              + deviceReset.get()
              + " stopSensorFeed="
              + stopFeedInvocations.get()
              + " feedRunning="
              + feedRunning.get()
              + "\n";
      Files.writeString(Path.of(countersFile), content);
    } catch (Exception e) {
      LOG.warn("failed to write counters file {}", countersFile, e);
    }
  }

  private static RolePermissionType[] operatorAndAdmin(PermissionType.Field... fields) {
    return new RolePermissionType[] {
      new RolePermissionType(Roles.OPERATOR, PermissionType.of(fields)),
      new RolePermissionType(Roles.ADMIN, PermissionType.of(fields))
    };
  }

  @Override
  public void onDataItemsCreated(java.util.List<DataItem> dataItems) {
    subscriptionModel.onDataItemsCreated(dataItems);
  }

  @Override
  public void onDataItemsModified(java.util.List<DataItem> dataItems) {
    subscriptionModel.onDataItemsModified(dataItems);
  }

  @Override
  public void onDataItemsDeleted(java.util.List<DataItem> dataItems) {
    subscriptionModel.onDataItemsDeleted(dataItems);
  }

  @Override
  public void onMonitoringModeChanged(java.util.List<MonitoredItem> monitoredItems) {
    subscriptionModel.onMonitoringModeChanged(monitoredItems);
  }
}
