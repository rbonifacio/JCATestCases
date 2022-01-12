package jca;

import java.security.SecureRandom;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import test.UsagePatternTestingFramework;
import javax.crypto.spec.GCMParameterSpec;

public class GCMParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void gCMParameterSpecValidTest1() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

	}

	@Test
	public void gCMParameterSpecValidTest2() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		int offset = 0;
		int len = 0;

		GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(96, genSeed, offset, len);
		Assertions.hasEnsuredPredicate(gCMParameterSpec0);
		Assertions.mustBeInAcceptingState(gCMParameterSpec0);

	}
}