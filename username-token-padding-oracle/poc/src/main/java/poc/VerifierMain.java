package poc;

import java.nio.file.Path;
import java.util.Properties;
import poc.common.Args;
import poc.common.PropsFile;

/**
 * Process 5 of 5: THE VERIFIER.
 *
 * <p>This is the only process, besides the orchestrator ({@code run.sh}), the server, and the
 * victim, that ever sees the victim's actual password -- and it receives it directly from the
 * orchestrator that generated it at runtime, never from {@link AttackerMain}. It compares that
 * ground truth against whatever {@link AttackerMain} independently recovered and wrote to its
 * out-file, and prints PASS/FAIL. The attacker prints its recovered answer without ever knowing,
 * from any information available to it, whether that answer is correct.
 */
public class VerifierMain {

  public static void main(String[] args) throws Exception {
    Args a = Args.parse(args);
    String expected = a.require("expected");
    String attackerOutFile = a.require("attacker-out-file");

    Properties out = PropsFile.load(Path.of(attackerOutFile));
    String recovered = out.getProperty("recoveredPassword");

    if (recovered != null && recovered.equals(expected)) {
      System.out.println("[+] VERIFIED: recovered password matches the victim's actual password (PASS)");
      System.out.println("VERIFY_RESULT=PASS");
      System.exit(0);
    } else {
      System.out.println("[-] MISMATCH: recovered password does not match the victim's actual password (FAIL)");
      System.out.println("VERIFY_RESULT=FAIL");
      System.exit(1);
    }
  }
}
