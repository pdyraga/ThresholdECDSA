package ACNS.ZeroKnowledgeProofs;

import ACNS.thresholdDSA.Util;
import ACNS.thresholdDSA.data.BitcoinParams;
import Common.Commitments.MultiTrapdoorCommitment;
import Common.Commitments.MultiTrapdoorMasterPublicKey;
import Common.Commitments.Open;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.Test;
import paillierp.Paillier;
import paillierp.key.KeyGen;
import paillierp.key.PaillierPrivateKey;

import java.math.BigInteger;
import java.security.SecureRandom;

import static Common.Commitments.MultiTrapdoorCommitment.generateNMMasterPublicKey;

public class Zkp_i2Test {

    @Test
    public void testZKPi2RoundTrip() {
        // GIVEN
        BigInteger secret = new BigInteger("5");

        PaillierPrivateKey paillierPrivateKey = KeyGen.PaillierKey(512, 122333356);
        Paillier paillier = new Paillier(paillierPrivateKey);
        paillier.setEncryption(paillierPrivateKey);

        PublicParameters zkpParams = Util.generateParamsforBitcoin(
                paillierPrivateKey.getK(),
                32,
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

        BigInteger eta1 = Util.randomFromZn(BitcoinParams.q, new SecureRandom());
        BigInteger eta2 = Util.randomFromZn(BitcoinParams.q.pow(6), new SecureRandom());

        BigInteger randomness = paillierPrivateKey.getPublicKey().getRandomModNStar();

        ECPoint c = curveParams.getG();
        BigInteger mask = paillier.encrypt(BitcoinParams.q.multiply(eta2).mod(paillierPrivateKey.getN()), randomness);
        BigInteger u = secret;
        BigInteger w = paillier.add(paillier.multiply(u, eta1), mask);

        ECPoint rI = BitcoinParams.G.multiply(eta1);

        MultiTrapdoorMasterPublicKey nmmpk = generateNMMasterPublicKey();
                MultiTrapdoorCommitment commitRiWi = MultiTrapdoorCommitment.multilinnearCommit(new SecureRandom(), nmmpk,new BigInteger(rI.getEncoded()), w);
        Open<BigInteger> openRiWi = commitRiWi.getOpen();


        ECPoint r = BitcoinParams.CURVE.getCurve().decodePoint(openRiWi.getSecrets()[0].toByteArray());

        // WHEN
        // Generate ZKP
        Zkp_i2 zkp2 = new Zkp_i2(zkpParams, eta1, eta2, new SecureRandom(), c, w, u, randomness);

        // THEN
        // Verify ZKP
        Assert.assertTrue("ZKP verification failed", zkp2.verify(zkpParams, curveParams, r, u, w));
    }

//
//    @Test
//    public void testZKPi1RoundTripNegative() {
//        // GIVEN
//        BigInteger secret = new BigInteger("12312312");
//
//        PaillierPrivateKey paillierPrivateKey = KeyGen.PaillierKey(512, 122333356);
//        Paillier paillier = new Paillier(paillierPrivateKey);
//        BigInteger r = paillierPrivateKey.getPublicKey().getRandomModNStar();
//        BigInteger c2 = Paillier.encrypt(secret, r, paillierPrivateKey); //encryptedDSAKey
//
//        BigInteger eta = Util.randomFromZn(BitcoinParams.q, new SecureRandom());
//        BigInteger c1 = paillier.multiply(c2, eta);
//        BigInteger c3 = paillier.encrypt(eta, r);
//
//
//        PublicParameters zkpParams = Util.generateParamsforBitcoin(
//                paillierPrivateKey.getK(),
//                15, // kPrime - provided some random value, need to understand what is it
//                new SecureRandom(),
//                paillierPrivateKey.getPublicKey()
//        );
//
//        X9ECParameters scp256k1Curve = SECNamedCurves.getByName("secp256k1");
//        ECDomainParameters curveParams = new ECDomainParameters(
//                scp256k1Curve.getCurve(),
//                scp256k1Curve.getG(),
//                scp256k1Curve.getN(),
//                scp256k1Curve.getH()
//        );
//
//        // Different ZKP Public Params which will be passed to verification
//        PublicParameters zkpParams2 = Util.generateParamsforBitcoin(
//                paillierPrivateKey.getK(),
//                15, // kPrime - provided some random value, need to understand what is it
//                new SecureRandom(),
//                paillierPrivateKey.getPublicKey()
//        );
//
//        // WHEN
//        // Generate ZKP
//        Zkp_i1 zkp1 = new Zkp_i1(zkpParams, eta, new SecureRandom(), r, c1, c2, c3);
//
//        // THEN
//        // Verify ZKP
//        Assert.assertFalse("ZKP verification is expected to fail but it passed", zkp1.verify(zkpParams2, curveParams, c1, c2, c3));
//    }
}
