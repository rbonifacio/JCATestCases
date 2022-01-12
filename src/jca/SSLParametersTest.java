package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import javax.net.ssl.SSLParameters;
import org.junit.Test;
import test.UsagePatternTestingFramework;

public class SSLParametersTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void sSLParametersValidTest1() {

		SSLParameters sSLParameters0 = new SSLParameters(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
				new String[] { "TLSv1.2" });
		Assertions.hasEnsuredPredicate(sSLParameters0);
		Assertions.mustBeInAcceptingState(sSLParameters0);

	}

	@Test
	public void sSLParametersValidTest2() {

		SSLParameters sSLParameters0 = new SSLParameters(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" });
		sSLParameters0.setProtocols(new String[] { "TLSv1.2" });
		Assertions.hasEnsuredPredicate(sSLParameters0);
		Assertions.mustBeInAcceptingState(sSLParameters0);

	}

	@Test
	public void sSLParametersValidTest3() {

		SSLParameters sSLParameters0 = new SSLParameters();
		sSLParameters0.setCipherSuites(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" });
		sSLParameters0.setProtocols(new String[] { "TLSv1.2" });
		Assertions.hasEnsuredPredicate(sSLParameters0);
		Assertions.mustBeInAcceptingState(sSLParameters0);

	}

	@Test
	public void sSLParametersValidTest4() {

		SSLParameters sSLParameters0 = new SSLParameters();
		sSLParameters0.setProtocols(new String[] { "TLSv1.2" });
		sSLParameters0.setCipherSuites(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" });
		Assertions.hasEnsuredPredicate(sSLParameters0);
		Assertions.mustBeInAcceptingState(sSLParameters0);

	}

	@Test
	public void sSLParametersInvalidTest1() {

		SSLParameters sSLParameters0 = new SSLParameters();
		Assertions.notHasEnsuredPredicate(sSLParameters0);
		Assertions.mustNotBeInAcceptingState(sSLParameters0);

	}

	@Test
	public void sSLParametersInvalidTest2() {

		SSLParameters sSLParameters0 = new SSLParameters(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" });
		Assertions.notHasEnsuredPredicate(sSLParameters0);
		Assertions.mustNotBeInAcceptingState(sSLParameters0);

	}

	@Test
	public void sSLParametersInvalidTest3() {

		SSLParameters sSLParameters0 = new SSLParameters();
		sSLParameters0.setCipherSuites(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" });
		Assertions.notHasEnsuredPredicate(sSLParameters0);
		Assertions.mustNotBeInAcceptingState(sSLParameters0);

	}

	@Test
	public void sSLParametersInvalidTest4() {

		SSLParameters sSLParameters0 = new SSLParameters();
		sSLParameters0.setProtocols(new String[] { "TLSv1.2" });
		Assertions.notHasEnsuredPredicate(sSLParameters0);
		Assertions.mustNotBeInAcceptingState(sSLParameters0);

	}
}