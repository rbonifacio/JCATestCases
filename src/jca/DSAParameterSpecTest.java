package jca;

import java.security.spec.DSAParameterSpec;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import org.junit.Test;
import java.math.BigInteger;
import test.UsagePatternTestingFramework;

public class DSAParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void dSAParameterSpecValidTest1() {

		BigInteger q = null;

		DSAParameterSpec dSAParameterSpec0 = new DSAParameterSpec(BigInteger.valueOf(1), q, BigInteger.valueOf(1));
		Assertions.hasEnsuredPredicate(dSAParameterSpec0);
		Assertions.mustBeInAcceptingState(dSAParameterSpec0);

	}
}