package jca;

import java.security.SecureRandom;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import javax.crypto.spec.PBEParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import test.UsagePatternTestingFramework;

public class PBEParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void pBEParameterSpecValidTest1() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		PBEParameterSpec pBEParameterSpec0 = new PBEParameterSpec(genSeed, 21552);
		Assertions.hasEnsuredPredicate(pBEParameterSpec0);
		Assertions.mustBeInAcceptingState(pBEParameterSpec0);

	}

	@Test
	public void pBEParameterSpecValidTest2() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		AlgorithmParameterSpec paramSpec = null;

		PBEParameterSpec pBEParameterSpec0 = new PBEParameterSpec(genSeed, 14636, paramSpec);
		Assertions.hasEnsuredPredicate(pBEParameterSpec0);
		Assertions.mustBeInAcceptingState(pBEParameterSpec0);

	}
}