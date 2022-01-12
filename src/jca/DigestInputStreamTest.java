package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.MessageDigest;
import java.security.DigestInputStream;
import org.junit.Test;
import java.io.IOException;
import test.UsagePatternTestingFramework;
import java.io.InputStream;

public class DigestInputStreamTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void digestInputStreamValidTest1() throws IOException {

		MessageDigest md = null;
		InputStream is = null;

		DigestInputStream digestInputStream0 = new DigestInputStream(is, md);
		digestInputStream0.read();
		Assertions.hasEnsuredPredicate(is);
		Assertions.mustBeInAcceptingState(digestInputStream0);

	}

	@Test
	public void digestInputStreamValidTest2() throws IOException {

		int off = 0;
		MessageDigest md = null;
		byte[] b = null;
		InputStream is = null;
		int len = 0;

		DigestInputStream digestInputStream0 = new DigestInputStream(is, md);
		digestInputStream0.read(b, off, len);
		Assertions.hasEnsuredPredicate(is);
		Assertions.mustBeInAcceptingState(digestInputStream0);

	}

	@Test
	public void digestInputStreamInvalidTest1() {

		MessageDigest md = null;
		InputStream is = null;

		DigestInputStream digestInputStream0 = new DigestInputStream(is, md);
		Assertions.notHasEnsuredPredicate(is);
		Assertions.mustNotBeInAcceptingState(digestInputStream0);

	}
}