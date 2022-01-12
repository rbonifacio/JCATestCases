package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import org.junit.Test;
import java.math.BigInteger;
import java.security.spec.RSAKeyGenParameterSpec;
import test.UsagePatternTestingFramework;

public class RSAKeyGenParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void rSAKeyGenParameterSpecValidTest1() {

		RSAKeyGenParameterSpec rSAKeyGenParameterSpec0 = new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(65537));
		Assertions.hasEnsuredPredicate(rSAKeyGenParameterSpec0);
		Assertions.mustBeInAcceptingState(rSAKeyGenParameterSpec0);

	}
}