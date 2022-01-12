package jca;

import java.io.OutputStream;
import java.security.DigestOutputStream;
import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.MessageDigest;
import org.junit.Test;
import java.io.IOException;
import test.UsagePatternTestingFramework;

public class DigestOutputStreamTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void digestOutputStreamValidTest1() throws IOException {

		MessageDigest md = null;
		OutputStream os = null;
		int b = 0;

		DigestOutputStream digestOutputStream0 = new DigestOutputStream(os, md);
		digestOutputStream0.write(b);
		Assertions.hasEnsuredPredicate(os);
		Assertions.mustBeInAcceptingState(digestOutputStream0);

	}

	@Test
	public void digestOutputStreamValidTest2() throws IOException {

		int off = 0;
		MessageDigest md = null;
		OutputStream os = null;
		byte[] data = null;
		int len = 0;

		DigestOutputStream digestOutputStream0 = new DigestOutputStream(os, md);
		digestOutputStream0.write(data, off, len);
		Assertions.hasEnsuredPredicate(os);
		Assertions.mustBeInAcceptingState(digestOutputStream0);

	}

	@Test
	public void digestOutputStreamInvalidTest1() {

		MessageDigest md = null;
		OutputStream os = null;

		DigestOutputStream digestOutputStream0 = new DigestOutputStream(os, md);
		Assertions.notHasEnsuredPredicate(os);
		Assertions.mustNotBeInAcceptingState(digestOutputStream0);

	}
}