package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.spec.DSAGenParameterSpec;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class DSAGenParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void dSAGenParameterSpecValidTest1() {

		int subPrimeQLen = 0;
		int primePLen = 0;

		DSAGenParameterSpec dSAGenParameterSpec0 = new DSAGenParameterSpec(primePLen, subPrimeQLen);
		Assertions.hasEnsuredPredicate(dSAGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dSAGenParameterSpec0);

	}

	@Test
	public void dSAGenParameterSpecValidTest2() {

		int subPrimeQLen = 0;
		int primePLen = 0;
		int seedLen = 0;

		DSAGenParameterSpec dSAGenParameterSpec0 = new DSAGenParameterSpec(primePLen, subPrimeQLen, seedLen);
		Assertions.hasEnsuredPredicate(dSAGenParameterSpec0);
		Assertions.mustBeInAcceptingState(dSAGenParameterSpec0);

	}
}