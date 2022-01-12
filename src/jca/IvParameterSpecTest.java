package jca;

import java.security.SecureRandom;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class IvParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void ivParameterSpecValidTest1() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		IvParameterSpec ivParameterSpec0 = new IvParameterSpec(genSeed);
		Assertions.hasEnsuredPredicate(ivParameterSpec0);
		Assertions.mustBeInAcceptingState(ivParameterSpec0);

	}

	@Test
	public void ivParameterSpecValidTest2() throws NoSuchAlgorithmException {

		int num = 0;

		SecureRandom secureRandom0 = SecureRandom.getInstance("SHA1PRNG");
		byte[] genSeed = secureRandom0.generateSeed(num);
		Assertions.hasEnsuredPredicate(genSeed);
		Assertions.mustBeInAcceptingState(secureRandom0);

		int offset = 0;
		int len = 0;

		IvParameterSpec ivParameterSpec0 = new IvParameterSpec(genSeed, offset, len);
		Assertions.hasEnsuredPredicate(ivParameterSpec0);
		Assertions.mustBeInAcceptingState(ivParameterSpec0);

	}
}