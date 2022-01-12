package jca;

import test.assertions.Assertions;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.DigestException;
import org.junit.Test;
import java.lang.String;
import test.UsagePatternTestingFramework;
import java.security.NoSuchProviderException;
import java.nio.ByteBuffer;

public class MessageDigestTest extends UsagePatternTestingFramework {
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;

	}

	@Test
	public void messageDigestValidTest1() throws NoSuchAlgorithmException {

		byte[] inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		byte[] inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256", (String) null);
		byte[] out = messageDigest0.digest(inbytearr);
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest3() throws NoSuchAlgorithmException {

		byte[] inbytearr = null;
		byte pre_inbyte = 0;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		messageDigest0.update(pre_inbyte);
		out = messageDigest0.digest();
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest4() throws NoSuchAlgorithmException, NoSuchProviderException {

		byte[] inbytearr = null;
		byte pre_inbyte = 0;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256", (String) null);
		byte[] out = messageDigest0.digest(inbytearr);
		messageDigest0.update(pre_inbyte);
		out = messageDigest0.digest();
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest5() throws NoSuchAlgorithmException {

		byte[] pre_inbytearr = null;
		byte[] inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		messageDigest0.update(pre_inbytearr);
		out = messageDigest0.digest();
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest6() throws NoSuchAlgorithmException {

		byte[] pre_inbytearr = null;
		int pre_off = 0;
		byte[] inbytearr = null;
		int pre_len = 0;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		messageDigest0.update(pre_inbytearr, pre_off, pre_len);
		out = messageDigest0.digest();
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest7() throws NoSuchAlgorithmException {

		byte[] inbytearr = null;
		ByteBuffer pre_inpBuf = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		messageDigest0.update(pre_inpBuf);
		out = messageDigest0.digest();
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest8() throws NoSuchAlgorithmException, DigestException {

		int off = 0;
		byte[] inbytearr = null;
		byte pre_inbyte = 0;
		int len = 0;
		byte[] out = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		out = messageDigest0.digest(inbytearr);
		messageDigest0.update(pre_inbyte);
		messageDigest0.digest(out, off, len);
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestValidTest9() throws NoSuchAlgorithmException {

		byte[] inbytearr = null;
		byte pre_inbyte = 0;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		messageDigest0.update(pre_inbyte);
		out = messageDigest0.digest(inbytearr);
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest1() throws NoSuchAlgorithmException {

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest2() throws NoSuchAlgorithmException, NoSuchProviderException {

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256", (String) null);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest3() throws NoSuchAlgorithmException {

		byte pre_inbyte = 0;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		messageDigest0.update(pre_inbyte);
		byte[] out = messageDigest0.digest();
		Assertions.notHasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest4() throws NoSuchAlgorithmException, NoSuchProviderException {

		byte pre_inbyte = 0;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256", (String) null);
		messageDigest0.update(pre_inbyte);
		byte[] out = messageDigest0.digest();
		Assertions.notHasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest5() throws NoSuchAlgorithmException {

		byte[] pre_inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		messageDigest0.update(pre_inbytearr);
		byte[] out = messageDigest0.digest();
		Assertions.notHasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest6() throws NoSuchAlgorithmException {

		byte[] pre_inbytearr = null;
		int pre_off = 0;
		int pre_len = 0;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		messageDigest0.update(pre_inbytearr, pre_off, pre_len);
		byte[] out = messageDigest0.digest();
		Assertions.notHasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest7() throws NoSuchAlgorithmException {

		ByteBuffer pre_inpBuf = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		messageDigest0.update(pre_inpBuf);
		byte[] out = messageDigest0.digest();
		Assertions.notHasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest8() throws NoSuchAlgorithmException, DigestException {

		int off = 0;
		byte pre_inbyte = 0;
		int len = 0;
		byte[] out = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		messageDigest0.update(pre_inbyte);
		messageDigest0.digest(out, off, len);
		Assertions.notHasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest9() throws NoSuchAlgorithmException {

		byte pre_inbyte = 0;
		byte[] inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		messageDigest0.update(pre_inbyte);
		byte[] out = messageDigest0.digest(inbytearr);
		Assertions.notHasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest10() throws NoSuchAlgorithmException {

		byte[] inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		out = messageDigest0.digest();
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest11() throws NoSuchAlgorithmException, NoSuchProviderException {

		byte[] inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256", (String) null);
		byte[] out = messageDigest0.digest(inbytearr);
		out = messageDigest0.digest();
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest12() throws NoSuchAlgorithmException, DigestException {

		int off = 0;
		byte[] inbytearr = null;
		int len = 0;
		byte[] out = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		out = messageDigest0.digest(inbytearr);
		messageDigest0.digest(out, off, len);
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}

	@Test
	public void messageDigestInvalidTest13() throws NoSuchAlgorithmException {

		byte[] inbytearr = null;

		MessageDigest messageDigest0 = MessageDigest.getInstance("SHA-256");
		byte[] out = messageDigest0.digest(inbytearr);
		out = messageDigest0.digest(inbytearr);
		Assertions.hasEnsuredPredicate(out);
		Assertions.mustNotBeInAcceptingState(messageDigest0);

	}
}