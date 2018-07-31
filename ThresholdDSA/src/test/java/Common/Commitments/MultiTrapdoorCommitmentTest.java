package Common.Commitments;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;


public class MultiTrapdoorCommitmentTest {

    @Test
    public void testCommitGenAndVerRoundTrip() {
        MultiTrapdoorMasterPublicKey publicKey = MultiTrapdoorCommitment.generateNMMasterPublicKey();
        BigInteger secret = BigInteger.valueOf(123456);

        MultiTrapdoorCommitment commitment = MultiTrapdoorCommitment.multilinnearCommit(new SecureRandom(), publicKey, secret);

        Assert.assertTrue(
                "Validation didn't pass for generated commitment",
                MultiTrapdoorCommitment.checkcommitment(commitment.getCommitment(), commitment.getOpen(), publicKey)
        );
    }

    @Test
    public void testCommitGenAndVerNegative() {
        MultiTrapdoorMasterPublicKey publicKey = MultiTrapdoorCommitment.generateNMMasterPublicKey();
        BigInteger secret = BigInteger.valueOf(123456);

        MultiTrapdoorCommitment commitment = MultiTrapdoorCommitment.multilinnearCommit(new SecureRandom(), publicKey, secret);


        publicKey = MultiTrapdoorCommitment.generateNMMasterPublicKey();

        Assert.assertFalse(
                "Validation didn't fail for changed publicKey",
                MultiTrapdoorCommitment.checkcommitment(commitment.getCommitment(), commitment.getOpen(), publicKey)
        );
    }
}
