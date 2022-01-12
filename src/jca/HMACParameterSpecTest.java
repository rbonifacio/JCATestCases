package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class HMACParameterSpecTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void hMACParameterSpecValidTest1() {

		int outputLength = 0;

		HMACParameterSpec hMACParameterSpec0 = new HMACParameterSpec(outputLength);
		Assertions.hasEnsuredPredicate(hMACParameterSpec0);
		Assertions.mustBeInAcceptingState(hMACParameterSpec0);

	}
}