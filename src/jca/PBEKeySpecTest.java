package jca;

import java.security.SecureRandom;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class PBEKeySpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void pBEKeySpecValidTest1() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		int keylength = 0;
		char[] password = null;

		PBEKeySpec pBEKeySpec0 = new PBEKeySpec(password, genSeed, 13289, keylength);
		Assertions.hasEnsuredPredicate(pBEKeySpec0);
		pBEKeySpec0.clearPassword();
		Assertions.mustBeInAcceptingState(pBEKeySpec0);

	}

	@Test
	public void pBEKeySpecInvalidTest1() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		int keylength = 0;
		char[] password = null;

		PBEKeySpec pBEKeySpec0 = new PBEKeySpec(password, genSeed, 13369, keylength);
		Assertions.hasEnsuredPredicate(pBEKeySpec0);
		Assertions.mustNotBeInAcceptingState(pBEKeySpec0);

	}
}