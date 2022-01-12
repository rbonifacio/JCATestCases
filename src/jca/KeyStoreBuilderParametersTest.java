package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.net.ssl.KeyStoreBuilderParameters;
import java.security.KeyStore.Builder;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class KeyStoreBuilderParametersTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void keyStoreBuilderParametersValidTest1() {

		Builder builder = null;

		KeyStoreBuilderParameters keyStoreBuilderParameters0 = new KeyStoreBuilderParameters(builder);
		Assertions.hasEnsuredPredicate(keyStoreBuilderParameters0);
		Assertions.mustBeInAcceptingState(keyStoreBuilderParameters0);

	}
}