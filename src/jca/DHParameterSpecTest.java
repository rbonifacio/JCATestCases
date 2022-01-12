package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import org.junit.Test;
import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import test.UsagePatternTestingFramework;

public class DHParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void dHParameterSpecValidTest1() {

		DHParameterSpec dHParameterSpec0 = new DHParameterSpec(BigInteger.valueOf(2), BigInteger.valueOf(2));
		Assertions.hasEnsuredPredicate(dHParameterSpec0);
		Assertions.mustBeInAcceptingState(dHParameterSpec0);

	}

	@Test
	public void dHParameterSpecValidTest2() {

		int l = 0;

		DHParameterSpec dHParameterSpec0 = new DHParameterSpec(BigInteger.valueOf(2), BigInteger.valueOf(1), l);
		Assertions.hasEnsuredPredicate(dHParameterSpec0);
		Assertions.mustBeInAcceptingState(dHParameterSpec0);

	}
}