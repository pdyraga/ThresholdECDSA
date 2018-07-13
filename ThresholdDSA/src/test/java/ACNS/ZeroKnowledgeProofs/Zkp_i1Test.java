package ACNS.ZeroKnowledgeProofs;

import ACNS.thresholdDSA.Util;
import ACNS.thresholdDSA.data.BitcoinParams;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.junit.Assert;
import org.junit.Test;
import paillierp.Paillier;
import paillierp.key.KeyGen;
import paillierp.key.PaillierPrivateKey;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Zkp_i1Test {

     @Test
    public void testZKPi1RoundTrip() {
        // GIVEN
        BigInteger secret = new BigInteger("5");

        PaillierPrivateKey paillierPrivateKey = KeyGen.PaillierKey(512, 122333356);
//         BigInteger p = BigInteger.valueOf(463);
//         BigInteger q = BigInteger.valueOf(631);

//         PaillierPrivateKey paillierPrivateKey = new PaillierPrivateKey(p,q,0);
        Paillier paillier = new Paillier(paillierPrivateKey);
         paillier.setEncryption(paillierPrivateKey);
//        BigInteger eta = Util.randomFromZn(BitcoinParams.q, new SecureRandom());
         BigInteger eta = BigInteger.valueOf(11);
//        BigInteger r = paillierPrivateKey.getPublicKey().getRandomModNStar();
         BigInteger r = BigInteger.valueOf(13);

        BigInteger c2 = Paillier.encrypt(secret, r, paillierPrivateKey); //encryptedDSAKey
        BigInteger c1 = paillier.multiply(c2, eta);
        BigInteger c3 = paillier.encrypt(eta, r);


        int kPrime = 32; // provided some random value, need to understand what is it
        PublicParameters zkpParams = Util.generateParamsforBitcoin(
                paillierPrivateKey.getK(),
                kPrime,
                new SecureRandom(),
                paillierPrivateKey.getPublicKey()
        );

        X9ECParameters scp256k1Curve = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters curveParams = new ECDomainParameters(
                scp256k1Curve.getCurve(),
                scp256k1Curve.getG(),
                scp256k1Curve.getN(),
                scp256k1Curve.getH()
        );

        // WHEN
        // Generate ZKP
        Zkp_i1 zkp1 = new Zkp_i1(zkpParams, eta, new SecureRandom(), r, c1, c2, c3);

        // THEN
        // Verify ZKP
        Assert.assertTrue("ZKP verification failed", zkp1.verify(zkpParams, curveParams, c1, c2, c3));
    }

    @Test
    public void testZKPi1RoundTripNegative() {
        // GIVEN
        BigInteger secret = new BigInteger("12312312");

        PaillierPrivateKey paillierPrivateKey = KeyGen.PaillierKey(512, 122333356);
        Paillier paillier = new Paillier(paillierPrivateKey);
        BigInteger r = paillierPrivateKey.getPublicKey().getRandomModNStar();
        BigInteger c2 = Paillier.encrypt(secret, r, paillierPrivateKey); //encryptedDSAKey

        BigInteger eta = Util.randomFromZn(BitcoinParams.q, new SecureRandom());
        BigInteger c1 = paillier.multiply(c2, eta);
        BigInteger c3 = paillier.encrypt(eta, r);


        PublicParameters zkpParams = Util.generateParamsforBitcoin(
                paillierPrivateKey.getK(),
                15, // kPrime - provided some random value, need to understand what is it
                new SecureRandom(),
                paillierPrivateKey.getPublicKey()
        );

        X9ECParameters scp256k1Curve = SECNamedCurves.getByName("secp256k1");
        ECDomainParameters curveParams = new ECDomainParameters(
                scp256k1Curve.getCurve(),
                scp256k1Curve.getG(),
                scp256k1Curve.getN(),
                scp256k1Curve.getH()
        );

        // Different ZKP Public Params which will be passed to verification
        PublicParameters zkpParams2 = Util.generateParamsforBitcoin(
                paillierPrivateKey.getK(),
                15, // kPrime - provided some random value, need to understand what is it
                new SecureRandom(),
                paillierPrivateKey.getPublicKey()
        );

        // WHEN
        // Generate ZKP
        Zkp_i1 zkp1 = new Zkp_i1(zkpParams, eta, new SecureRandom(), r, c1, c2, c3);

        // THEN
        // Verify ZKP
        Assert.assertFalse("ZKP verification is expected to fail but it passed", zkp1.verify(zkpParams2, curveParams, c1, c2, c3));
    }
}
