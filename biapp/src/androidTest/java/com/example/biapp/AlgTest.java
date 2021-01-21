package com.example.biapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.util.AlgUtil;
import com.biapp.util.CertUtil;
import com.biapp.util.PrintfUtil;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA512Digest;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import aura.data.Bytes;
import aura.data.Strings;


@RunWith(AndroidJUnit4.class)
public class AlgTest {

    @Test
    public void symmetryTest() {
        byte[] key8 = new byte[8];
        byte[] key16 = new byte[16];
        byte[] key24 = new byte[24];
        byte[] key32 = new byte[32];
        byte[] iv8 = new byte[8];
        byte[] iv16 = new byte[16];
        byte[] data = new SecureRandom().generateSeed(125);
        byte[] encrypt_DES = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.DES,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key8, iv8, data);
        byte[] encrypt_TDES = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.TDES,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key24, iv8, data);
        byte[] encrypt_AES = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.AES,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key32, iv16, data);
        byte[] encrypt_SM4 = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.SM4,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.PKCS5Padding, key16, iv16, data);

        PrintfUtil.d("DES",
                "" + Bytes.toHexString(AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.DES,
                        AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key8, iv8,
                        encrypt_DES)).equals(Bytes.toHexString(data)));
        PrintfUtil.d("TDES",
                "" + Bytes.toHexString(AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.TDES,
                        AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key24, iv8,
                        encrypt_TDES)).equals(Bytes.toHexString(data)));
        PrintfUtil.d("AES",
                "" + Bytes.toHexString(AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.AES,
                        AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key32, iv16,
                        encrypt_AES)).equals(Bytes.toHexString(data)));
        PrintfUtil.d("SM4",
                "" + Bytes.toHexString(AlgUtil.decrypt(AlgUtil.SymmetryAlgorithm.SM4,
                        AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.PKCS5Padding, key16,
                        iv16, encrypt_SM4)).equals(Bytes.toHexString(data)));
    }

    @Test
    public void hashTest() {
        byte[] data = new SecureRandom().generateSeed(125);
        PrintfUtil.d("SHA256", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA256, data)));
        PrintfUtil.d("SHA384", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA384, data)));
        PrintfUtil.d("SHA512", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA512, data)));
        PrintfUtil.d("SM3", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SM3, data)));
    }

    @Test
    public void iso9797_1Test() {
        String string1 = "Now is the time for all ";
        String string2 = "Now is the time for it";
        PrintfUtil.d("Str1-Method1", Bytes.toHexString(AlgUtil.ISO9797_1Padding_Method1(8, string1.getBytes())));
        PrintfUtil.d("Str1-Method2", Bytes.toHexString(AlgUtil.ISO9797_1Padding_Method2(8, string1.getBytes())));
        PrintfUtil.d("Str1-Method3", Bytes.toHexString(AlgUtil.ISO9797_1Padding_Method3(8, string1.getBytes())));

        PrintfUtil.d("Str2-Method1", Bytes.toHexString(AlgUtil.ISO9797_1Padding_Method1(8, string2.getBytes())));
        PrintfUtil.d("Str2-Method2", Bytes.toHexString(AlgUtil.ISO9797_1Padding_Method2(8, string2.getBytes())));
        PrintfUtil.d("Str2-Method3", Bytes.toHexString(AlgUtil.ISO9797_1Padding_Method3(8, string2.getBytes())));

        String key1 = "0123456789ABCDEF";
        PrintfUtil.d("Str1-ISO9797-1MACAlgorithm1-Method1", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm1(Bytes.fromHexString(key1), string1.getBytes(), AlgUtil.MacAlgorithmPadding.Method1)));
        PrintfUtil.d("Str1-ISO9797-1MACAlgorithm1-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm1(Bytes.fromHexString(key1), string1.getBytes(), AlgUtil.MacAlgorithmPadding.Method2)));
        PrintfUtil.d("Str1-ISO9797-1MACAlgorithm1-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm1(Bytes.fromHexString(key1), string1.getBytes(), AlgUtil.MacAlgorithmPadding.Method3)));

        PrintfUtil.d("Str2-ISO9797-1MACAlgorithm1-Method1", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm1(Bytes.fromHexString(key1), string2.getBytes(), AlgUtil.MacAlgorithmPadding.Method1)));
        PrintfUtil.d("Str2-ISO9797-1MACAlgorithm1-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm1(Bytes.fromHexString(key1), string2.getBytes(), AlgUtil.MacAlgorithmPadding.Method2)));
        PrintfUtil.d("Str2-ISO9797-1MACAlgorithm1-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm1(Bytes.fromHexString(key1), string2.getBytes(), AlgUtil.MacAlgorithmPadding.Method3)));

        String key2 = "0123456789ABCDEFFEDCBA9876543210";
        PrintfUtil.d("Str1-ISO9797-1MACAlgorithm3-Method1", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm3(Bytes.fromHexString(key2), string1.getBytes(), AlgUtil.MacAlgorithmPadding.Method1)));
        PrintfUtil.d("Str1-ISO9797-1MACAlgorithm3-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm3(Bytes.fromHexString(key2), string1.getBytes(), AlgUtil.MacAlgorithmPadding.Method2)));
        PrintfUtil.d("Str1-ISO9797-1MACAlgorithm3-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm3(Bytes.fromHexString(key2), string1.getBytes(), AlgUtil.MacAlgorithmPadding.Method3)));

        PrintfUtil.d("Str2-ISO9797-1MACAlgorithm3-Method1", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm3(Bytes.fromHexString(key2), string2.getBytes(), AlgUtil.MacAlgorithmPadding.Method1)));
        PrintfUtil.d("Str2-ISO9797-1MACAlgorithm3-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm3(Bytes.fromHexString(key2), string2.getBytes(), AlgUtil.MacAlgorithmPadding.Method2)));
        PrintfUtil.d("Str2-ISO9797-1MACAlgorithm3-Method2", Bytes.toHexString(AlgUtil.ISO9797_1_MACAlgorithm3(Bytes.fromHexString(key2), string2.getBytes(), AlgUtil.MacAlgorithmPadding.Method3)));

    }

    @Test
    public void ingenicKCVTest() {
        PrintfUtil.d("DES", "" + Bytes.toHexString(AlgUtil.desLegacyKCV(Bytes.fromHexString("2222222222222222"))).substring(0, 6).equals("00962B"));
        PrintfUtil.d("DES_16", "" + Bytes.toHexString(AlgUtil.tdesLegacyKCV(Bytes.fromHexString("22222222222222224444444444444444"))).substring(0, 6).equals("3A42D7"));
        PrintfUtil.d("DES_24", "" + Bytes.toHexString(AlgUtil.tdesLegacyKCV(Bytes.fromHexString("222222222222222244444444444444446666666666666666"))).substring(0, 6).equals("1A0465"));
        PrintfUtil.d("AES_128", "" + Bytes.toHexString(AlgUtil.aesCMACKCV(Bytes.fromHexString("22222222222222224444444444444444"))).substring(0, 6).equals("0A0F92"));
        PrintfUtil.d("AES_192", "" + Bytes.toHexString(AlgUtil.aesCMACKCV(Bytes.fromHexString("222222222222222244444444444444446666666666666666"))).substring(0, 6).equals("E4CEC0"));
        PrintfUtil.d("AES_256", "" + Bytes.toHexString(AlgUtil.aesCMACKCV(Bytes.fromHexString("2222222222222222444444444444444466666666666666668888888888888888"))).substring(0, 6).equals("AD77D6"));

        PrintfUtil.d("HMAC_16", "" + Bytes.toHexString(AlgUtil.ingenicHMACKCV(Bytes.fromHexString("22222222222222224444444444444444"))).substring(0, 6).equals("3E3CD3"));
        PrintfUtil.d("HMAC_24", "" + Bytes.toHexString(AlgUtil.ingenicHMACKCV(Bytes.fromHexString("222222222222222244444444444444446666666666666666"))).substring(0, 6).equals("D3A95C"));
        PrintfUtil.d("HMAC_32", "" + Bytes.toHexString(AlgUtil.ingenicHMACKCV(Bytes.fromHexString("2222222222222222444444444444444466666666666666668888888888888888"))).substring(0, 6).equals("67E44C"));
    }

    @Test
    public void ingenicDCVTest() {
        PrintfUtil.d("SecretClientDATA(>=16)", "" + Bytes.toHexString(AlgUtil.ingenicDCV(Bytes.fromHexString("2222222222222222444444444444444466666666666666668888888888888888"), true)).substring(0, 6).equals("18310F"));
        PrintfUtil.d("SecretClientDATA(=8)", "" + Bytes.toHexString(AlgUtil.ingenicDCV(Bytes.fromHexString("2222222222222222"), true)).substring(0, 6).equals("00962B"));
        PrintfUtil.d("CleartextClientDATA", "" + Bytes.toHexString(AlgUtil.ingenicDCV(Bytes.fromHexString("2222222222222222444444444444444466666666666666668888888888888888"), false)).substring(0, 6).equals("18310F"));
    }


    @Test
    public void rsaHexTest() {
        for (int i = 0; i < 1000; i++) {
            PrintfUtil.d("checkRound", (i + 1) + "");
            byte[] hash = new SecureRandom().generateSeed(32);
            KeyPair keyPair = AlgUtil.generateRSAKeyPair(2048, 3);
            String publickHex = Bytes
                    .toHexString(CertUtil.RSAPublicKey2Hex((RSAPublicKey) keyPair.getPublic()));
            PrintfUtil.d("pub", publickHex);
            String privateHex = Bytes.toHexString(
                    CertUtil.RSAPrivateCrtKey2Hex((RSAPrivateCrtKey) keyPair.getPrivate()));
            PrintfUtil.d("pri", privateHex);
            byte[] signed1 = AlgUtil.RSASign(AlgUtil.RSASignType.NONEwithRSA,
                    (RSAPrivateCrtKey) keyPair.getPrivate(), hash);
            boolean check1 = AlgUtil.RSASignVerify(AlgUtil.RSASignType.NONEwithRSA,
                    CertUtil.hex2RSAPublicKey(publickHex), hash, signed1);
            if (!check1) {
                PrintfUtil.e("check1", check1 + "");
            }
            byte[] signed2 = AlgUtil.RSASign(AlgUtil.RSASignType.NONEwithRSA,
                    CertUtil.hex2RSAPrivateKey(privateHex), hash);
            boolean check2 = AlgUtil.RSASignVerify(AlgUtil.RSASignType.NONEwithRSA,
                    (RSAPublicKey) keyPair.getPublic(), hash, signed2);
            if (!check2) {
                PrintfUtil.e("check2", check2 + "");
            }
        }
    }

    @Test
    public void rsaTest() {
        String publicKeyHex = "00080000BCDDE53C4254AFBBDF3E196A8C8D0507F02AB8B25EB81FEEACD21966F6016A9F9B36EA0BE71E623C4E14A5719139971C1CC691FE132E0E6E466164ECA0ACB9517CDFEB752473FE81BF9C1A61A67FE309C00A5855409348B78F348E38198CB8F188C68C772E3F3699E4920CD780D09638F1334757EE9C4463799DBEBE2DFB9649EA2C74C53B2C9974DC28AA18C2408351B9A0C4CD95D8E6A40E4589DF59A230763C3CE80955F2F3E8E572B049E50A3F205B4F8D572E0EBB03B2ED17B8DF547962AA9C818209FE261B5631C930A7DD294AC35367793505EF5692420EB0D1FDD92E7C62101A8DA3ADE1D7C1F33985027366AEA708AED770EA58FFBD55CC0159108F00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
        RSAPublicKey rsaPublicKey = CertUtil.hex2RSAPublicKey(publicKeyHex);
        String privateKeyHex = "00080000BCDDE53C4254AFBBDF3E196A8C8D0507F02AB8B25EB81FEEACD21966F6016A9F9B36EA0BE71E623C4E14A5719139971C1CC691FE132E0E6E466164ECA0ACB9517CDFEB752473FE81BF9C1A61A67FE309C00A5855409348B78F348E38198CB8F188C68C772E3F3699E4920CD780D09638F1334757EE9C4463799DBEBE2DFB9649EA2C74C53B2C9974DC28AA18C2408351B9A0C4CD95D8E6A40E4589DF59A230763C3CE80955F2F3E8E572B049E50A3F205B4F8D572E0EBB03B2ED17B8DF547962AA9C818209FE261B5631C930A7DD294AC35367793505EF5692420EB0D1FDD92E7C62101A8DA3ADE1D7C1F33985027366AEA708AED770EA58FFBD55CC0159108F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000118D53033E920CB6E6F5EF1E6918E652FF3031AFFD0F672B46622C5D644D850D5A589E5E224C458F446EBEE08EDA85DD7036D947A8CB90C8AB15452F9CDF287F74FECFD3F8CC8779945C157B2A93ABD7665BAB67C971E067CA426ABE072738F49AACB3862DF40CE84138AA4879D574FB932F5A416CAB7DF42191685A2E9D6DF9EA485ED01EFD54528BBC3F327385968A707B7649948ED0FB84698E1BA378D7C59968DAE93EBC265F5AD963FFB3FA0DC3E931427CCCB3247DEF5E0E3C57949CA9E4A28FAB98D92BFB69CD84B308DB69977A0F4E463D68FAC81B4D2DBBBADD657DCE0972743362AC500A77338971993ABEB0B69479F0874CAFAA025B0E1247B0D91E106CDD008C9150914938A8CA5D784B856154238B7E78E89CBD6569F597620107F5E6EE1C3EA314190E08E24475EB816F1211ED149FF9533E560DE4CAEAEF675118B96D5454596EE88A33DD9A1176642AE757BC6180A0D7839B55E9916C62DD6AB021B611EA50E9BEE7492C71092917067A0D0486DC88C35DC8B45EF4B554D59D6DCF06E78F87281AD5BEFB613101B22DEACCDDF7ACB630E1966E6DDAFAB9B40F6147AD47EAF326A61ACAD146D17D1CCFA46D3812337BA5184C40EB0D0BD298FD802C75D778EF5645777AAE527E4A74E7A83BE9483C2C7B6ACC9655BFC28F8EF86DD4D2806BF4ECF2E8E960FD12290DD9C02E45844E22AFF0207FE5E60FB8827089BA505DF4029F0D5FBAAE22479F116C81C3A13475DB1432E2BFDD64CAACB21366E1B59C18FD4E088353EDABE6C2E289A82C4D606B9A3308006CB9A2D587E0F0E63C39A56F3098A086A0E34A407EC1E82E3F59F274E4323A5397DEBE7461F7CC5BFE7E23834E2312ED700C262ACE8A95F1D74BA4090DA6439128ED34F936CC91CB332626F42307965E0ABEA542D889265D00B47D8AD263411EC8ED5F9CB2057D306F549410AC1DF37E0CAD5B9A4BEDF7466D585A060A740904D67F0F250F22646A2486311BF44C3FC72FD9ED26F5671C327A9E3489E51F2F2AD8C1E775639BA34F78680DC35DD9F0B06FCC06C1D03E0B62024C42D9F5042F3D08187B5C8A36DB79E5B053FC7C4A701BB57A488C50A82CC706067E2FA18A733841669854E789FA628C0B4EC5B53FDA6648C7D1A5C3C338B6274E1F51B9D5F914E5873A5A1313470FE1B307AB75C1BA922EEE00412B0C333A12AE5C799FA33BBAE0BCCFA48E9623B99AC6C415CA40A29EF287CC1DFFD6F90FF7A2BA761CD79C14B1BDEA53D1875";
        RSAPrivateCrtKey rsaPrivateKey = CertUtil.hex2RSAPrivateKey(privateKeyHex);
        String data = "1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz";
        String signHex = "4336354FCC76BD3E0A5C533EA569E9EDC133CA5895579A74D00E9140B2ACDECA3762CE01BBFC56C2B98AE1E8DDB0F1235CBB5239DD2D56E8320301362BB5D92310DCA23CB246772C6CB0FBFBC571D1107FB5EAF0E698E52B7002AAE70E55B9A3254154EB204F3E17D67D503056BBDBA4CD3F2AB131102BDFBE5EBE5D2766579E7F33489BABDDB54D766AF0A0B8039CCA7E77E7D1662D34C06D5E08D46961562B29597DE01AF23DAA296EA7E5AA631557B22FDBD643BAD0A632D83B0B097C15B03E33382AB0865C0A13D57C1AC39673AA48C558C448EF8498950ACBC0209DD73C82B4CEB7C8C3D34EFD70F0BC2CD9EF55883DBA5B14BD9066066ED800453890B4";

        PrintfUtil.d("Check-PublicKey",
                Bytes.toHexString(AlgUtil.RSAPublicKeyCalc(AlgUtil.AsymmetricPadding.NoPadding,
                        rsaPublicKey, data.getBytes())).equals(signHex) + "");
        PrintfUtil.d("Check-PrivateKey",
                Strings.decode(AlgUtil.RSAPrivateKeyCalc(AlgUtil.AsymmetricPadding.NoPadding,
                        rsaPrivateKey, Bytes.fromHexString(signHex))).equals(data) + "");

        KeyPair keyPair = AlgUtil.generateRSAKeyPair(1024, 65535);
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        PrintfUtil.d("PrivateKey", Bytes.toHexString(CertUtil.RSAPrivateCrtKey2Hex(privateKey)));
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        PrintfUtil.d("PublicKey", Bytes.toHexString(CertUtil.RSAPublicKey2Hex(publicKey)));
        byte[] hash256 = AlgUtil.hash(AlgUtil.HashAlgorithm.SHA256, data.getBytes());
        PrintfUtil.d("Hash256", Bytes.toHexString(hash256));
        byte[] sha256withRSA = AlgUtil.RSASign(AlgUtil.RSASignType.SHA256withRSA, privateKey, data.getBytes());
        PrintfUtil.d("Sha256withRSA", Bytes.toHexString(sha256withRSA));
        PrintfUtil.d("Sha256withRSA-Decrypt", Bytes.toHexString(AlgUtil
                .RSAPublicKeyCalc(AlgUtil.AsymmetricPadding.NoPadding, publicKey, sha256withRSA)));
        PrintfUtil.d("Check-SHA256withRSA", "" + AlgUtil.RSASignVerify(AlgUtil.RSASignType.SHA256withRSA, publicKey,
                data.getBytes(), sha256withRSA));
        byte[] sha256withRSA_PSS = AlgUtil.RSASign(AlgUtil.RSASignType.SHA256withRSA_PSS, privateKey, data.getBytes());
        PrintfUtil.d("SHA256withRSA/PSS", Bytes.toHexString(sha256withRSA_PSS));
        PrintfUtil.d("Check-SHA256withRSA/PSS", "" + AlgUtil.RSASignVerify(AlgUtil.RSASignType.SHA256withRSA_PSS,
                publicKey, data.getBytes(), sha256withRSA_PSS));
    }

    @Test
    public void eccHexTest() {
        AlgUtil.ECCCurve eccCurve = AlgUtil.ECCCurve.secp256r1;
        for (int i = 0; i < 1000; i++) {
            PrintfUtil.d("checkRound", (i + 1) + "");
            byte[] hash = new SecureRandom().generateSeed(32);
            KeyPair eccKeyPairs = AlgUtil.generateECCKeyPair(eccCurve);
            String publickHex = Bytes.toHexString(CertUtil.ECPublicKey2Hex((ECPublicKey) eccKeyPairs.getPublic()));
            String privateHex = Bytes.toHexString(CertUtil.ECPrivateKey2Hex((ECPrivateKey) eccKeyPairs.getPrivate()));
            byte[] signed1 = AlgUtil.ECCSign(AlgUtil.ECCSignType.NONEwithECDSA, (ECPrivateKey) eccKeyPairs.getPrivate(), hash);
            boolean check1 = AlgUtil.ECCSignVerify(AlgUtil.ECCSignType.NONEwithECDSA, CertUtil.hex2ECPublicKey(eccCurve, publickHex), hash, signed1);
            if (!check1) {
                PrintfUtil.e("check1", check1 + "");
            }
            byte[] signed2 = AlgUtil.ECCSign(AlgUtil.ECCSignType.NONEwithECDSA, CertUtil.hex2ECPrivateKey(eccCurve, privateHex), hash);
            boolean check2 = AlgUtil.ECCSignVerify(AlgUtil.ECCSignType.NONEwithECDSA, (ECPublicKey) eccKeyPairs.getPublic(), hash, signed2);
            if (!check2) {
                PrintfUtil.e("check2", check2 + "");
            }
        }
    }

    @Test
    public void eccTest() {
        byte[] hash = Bytes.fromHexString("E92A371FBE7270BC1B4A708C0DEECFBF24BD76A4802A13CECC0AECADCB24BB98");
        KeyPair keypair256 = AlgUtil.generateECCKeyPair(AlgUtil.ECCCurve.secp256r1);
        ECPrivateKey privateKey256 = (ECPrivateKey) keypair256.getPrivate();
        ECPublicKey publicKey256 = (ECPublicKey) keypair256.getPublic();
        byte[] signed256 = AlgUtil.ECCSign(AlgUtil.ECCSignType.SHA256withECDSA, privateKey256, hash);
        PrintfUtil.d("ECC-256-Signed", Bytes.toHexString(signed256));
        PrintfUtil.d("ECC-256-Signed-R", Bytes.toHexString(AlgUtil.parseECCSigned(signed256).getR()));
        PrintfUtil.d("ECC-256-Signed-S", Bytes.toHexString(AlgUtil.parseECCSigned(signed256).getS()));
        PrintfUtil.d("ECC-256-Signed", Bytes.toHexString(new AlgUtil.ECCSigned(AlgUtil.parseECCSigned(signed256).getR(), AlgUtil.parseECCSigned(signed256).getS()).getSigned()));
        PrintfUtil.d("Check-ECC-256-Signed",
                "" + AlgUtil.ECCSignVerify(AlgUtil.ECCSignType.SHA256withECDSA, publicKey256, hash, signed256));

        KeyPair keypair521 = AlgUtil.generateECCKeyPair(AlgUtil.ECCCurve.secp521r1);
        ECPrivateKey privateKey521 = (ECPrivateKey) keypair521.getPrivate();
        ECPublicKey publicKey521 = (ECPublicKey) keypair521.getPublic();
        byte[] signed521 = AlgUtil.ECCSign(AlgUtil.ECCSignType.SHA256withECDSA, privateKey521, hash);
        PrintfUtil.d("ECC-521-Signed", Bytes.toHexString(signed521));
        PrintfUtil.d("ECC-521-Signed-R", Bytes.toHexString(AlgUtil.parseECCSigned(signed521).getR()));
        PrintfUtil.d("ECC-521-Signed-S", Bytes.toHexString(AlgUtil.parseECCSigned(signed521).getS()));
        PrintfUtil.d("ECC-521-Signed", Bytes.toHexString(new AlgUtil.ECCSigned(AlgUtil.parseECCSigned(signed521).getR(), AlgUtil.parseECCSigned(signed521).getS()).getSigned()));
        PrintfUtil.d("Check-ECC-521-Signed",
                "" + AlgUtil.ECCSignVerify(AlgUtil.ECCSignType.SHA256withECDSA, publicKey521, hash, signed521));

        byte[] publicKey = Bytes.fromHexString(
                "04E811C1E649E9EA7D2DD5432B53AE5154CA7AAFF0A23B2BD2E70B97AB74EC70122350BC22B5602B5714159BF9A910003DD723CF2E2D8CE73269C1BBC3C26441D7");
        byte[] privateKey = Bytes
                .fromHexString("B5A3C547A0EC14EAA144DDE6757C9AFB5C7082730CB286659B4E97888955075E");
        byte[] signed = Bytes.fromHexString(
                "30440220683C82EE5FC586D2CA76C82CC5669A4D4E29FEE3283F6D9C87ED85E873918CC102200C726F027F0B88BBF2196912FE46BB0735D090DEEDA9F3A6EC4DBC1FCDDE5F1C");
        ECPrivateKey ecPrivateKey = CertUtil.hex2ECPrivateKey(AlgUtil.ECCCurve.secp256r1,
                Bytes.toHexString(privateKey));
        byte[] mySign = AlgUtil.ECCSign(AlgUtil.ECCSignType.SHA256withECDSA, ecPrivateKey, hash);
        PrintfUtil.d("MySign", Bytes.toHexString(mySign));
        ECPublicKey ecPublicKey = CertUtil.hex2ECPublicKey(AlgUtil.ECCCurve.secp256r1,
                Bytes.toHexString(publicKey));
        PrintfUtil.d("Check-MySign", "" + AlgUtil.ECCSignVerify(AlgUtil.ECCSignType.SHA256withECDSA,
                ecPublicKey, hash, mySign));
    }

    @Test
    public void ecdhTest() {
        KeyPair keyPair1 = AlgUtil.generateECCKeyPair(AlgUtil.ECCCurve.secp256r1);
        KeyPair keyPair2 = AlgUtil.generateECCKeyPair(AlgUtil.ECCCurve.secp256r1);
        byte[] sharedKey1 = AlgUtil.getShareKey((ECPrivateKey) keyPair1.getPrivate(), (ECPublicKey) keyPair2.getPublic());
        PrintfUtil.d("ShareKey1", Bytes.toHexString(sharedKey1));
        byte[] sharedKey2 = AlgUtil.getShareKey((ECPrivateKey) keyPair2.getPrivate(), (ECPublicKey) keyPair1.getPublic());
        PrintfUtil.d("ShareKey2", Bytes.toHexString(sharedKey2));
        PrintfUtil.d("ShareKey", "" + Bytes.toHexString(sharedKey1).equals(Bytes.toHexString(sharedKey2)));
    }

    @Test
    public void ikTest() {
        byte[] ck1 = Bytes.fromHexString("11111111111111111111111111111111");
        byte[] ksn1 = Bytes.fromHexString("FFFFFF910626A4E00000");
        byte[] expect1 = Bytes.fromHexString("E9758033708B76CACDE1744D4633E164");
        byte[] ik1 = AlgUtil.tdesIK(ck1, ksn1);
        PrintfUtil.d("TDES-IK", Bytes.toHexString(ik1));
        PrintfUtil.d("TDES-IKExpect", Bytes.equals(ik1, expect1) + "");

        byte[] ck2 = Bytes.fromHexString("FEDCBA9876543210F1F1F1F1F1F1F1F1");
        byte[] ksn2 = Bytes.fromHexString("123456789012345612345678");
        byte[] expect2 = Bytes.fromHexString("1273671EA26AC29AFA4D1084127652A1");
        byte[] ik2 = AlgUtil.aesIK(ck2, ksn2);
        PrintfUtil.d("AES-IK", Bytes.toHexString(ik2));
        PrintfUtil.d("AES-IKExpect", Bytes.equals(ik2, expect2) + "");
    }

    @Test
    public void ksnAddTest() {
        String newKsn1 = AlgUtil.ksnAdd1("12345678901234567890");
        PrintfUtil.d("newKsn1", newKsn1);
        String newKsn2 = AlgUtil.ksnAdd1("123456789012345678901234");
        PrintfUtil.d("newKsn2", newKsn2);
    }

    @Test
    public void hmacTest() {
        byte[] data = Strings.encode("Sample message for keylen=blocklen");
        byte[] key = Bytes.fromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");
        byte[] hmac = Bytes.fromHexString("8BB9A1DB9806F20DF7F77B82138C7914D174D59E13DC4D0169C9057B133E1D62");
        byte[] result1 = AlgUtil.hmac(new SHA256Digest(), key, data);
        PrintfUtil.d("Result1", "" + Bytes.equals(result1, hmac));

        data = Strings.encode("Sample message for keylen<blocklen");
        key = Bytes.fromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        hmac = Bytes.fromHexString("A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790");
        byte[] result2 = AlgUtil.hmac(new SHA256Digest(), key, data);
        PrintfUtil.d("Result2", "" + Bytes.equals(result2, hmac));

        data = Strings.encode("Sample message for keylen=blocklen");
        key = Bytes.fromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263");
        hmac = Bytes.fromHexString("BDCCB6C72DDEADB500AE768386CB38CC41C63DBB0878DDB9C7A38A431B78378D");
        byte[] result3 = AlgUtil.hmac(new SHA256Digest(), key, data);
        PrintfUtil.d("Result3", "" + Bytes.equals(result3, hmac));

        data = Strings.encode("Sample message for keylen<blocklen, with truncated tag");
        key = Bytes.fromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30");
        hmac = Bytes.fromHexString("27A8B157839EFEAC98DF070B331D593618DDB985D403C0C786D23B5D132E57C7");

        byte[] result4 = AlgUtil.hmac(new SHA256Digest(), key, data);
        PrintfUtil.d("Result4", "" + Bytes.equals(result4, hmac));
    }

    @Test
    public void hkdfTest() {
        String shareKey1 = "EC0E9A9C792913CE0F4011E1FD259A118456BB422AF5DEB4786097809B78F2D3";
        String expect1 = "6060B85FAEA3C55635F613F3DFB6AB2B";
        byte[] tk1 = AlgUtil.hkdf(new SHA256Digest(), Strings.encode("kld-ik-inject-salt"), Strings.encode("kld-ik-inject"), Bytes.fromHexString(shareKey1), 16);
        PrintfUtil.d("t1", "" + Bytes.toHexString(tk1).equals(expect1));

        String shareKey2 = "01F44B719841030FDC878B581BDAF1330A63248669B4B3955A4CA6FCFE58B18D75E5E24F95981CC115D209B443D5B29858D794723FFEC458585C860076814C2EC427";
        String expect2 = "5EA7470C4E7C3505D5308C535E60DBA8D9725E4FCACAA36BF759CCB144151AB8";
        byte[] tk2 = AlgUtil.hkdf(new SHA256Digest(), Strings.encode("kld-ik-inject-salt"), Strings.encode("kld-ik-inject"), Bytes.fromHexString(shareKey2), 32);
        PrintfUtil.d("t2", "" + Bytes.toHexString(tk2).equals(expect2));

        String shareKey3 = "01AEE05CDD3A48FFD95AC5A4DFEFC23A2401C293DF4B476F717B00346458C380D82EF89C2BB2DDBA0F3008C498D6E4BF3A77EB3F48878C34180F475D1F6745913A41";
        String expect3 = "8DC386B27EF9BA7D0C9FA303E029A83F51B5F77F0E5F3B304FB1610FC1E1EBF3";
        byte[] tk3 = AlgUtil.hkdf(new SHA256Digest(), Strings.encode("kld-ik-inject-salt"), Strings.encode("kld-ik-inject"), Bytes.fromHexString(shareKey3), 32);
        PrintfUtil.d("t3", "" + Bytes.toHexString(tk3).equals(expect3));
    }

    @Test
    public void ingenicoECDHTest() {
        String KRD_priv = "001B27EAEE67A9F7C8442D3C78F1CE176ED85C16C6ABD65D08981B9798B4DBA0DBA24FA9672233C78E2C3B0EEF2D64FE39568155070B37E378FD1E2698F81598C673";
        String KRD_pub = "040158F957A7BD15A84DEEE67BE9D097D58482DD389E506572C034299B98BC67E50BA1F280D787B19EA334398A09F8864605D3A7B8311F0A2625418CD194058A887CCD01D5C764FEE682D47781CDACD98765FDD5538724201386DA40FDD8B5843D32A0444B52ED5AFF7EB40DD60484728764DD53121053F79D23EC1457341DDD58D0651947";
        String KRD_nonce = "518F618D09A9A767545EA504ABB39434";
        String KRD_pub_x = "0158F957A7BD15A84DEEE67BE9D097D58482DD389E506572C034299B98BC67E50BA1F280D787B19EA334398A09F8864605D3A7B8311F0A2625418CD194058A887CCD";
        String KRD_pub_y = "01D5C764FEE682D47781CDACD98765FDD5538724201386DA40FDD8B5843D32A0444B52ED5AFF7EB40DD60484728764DD53121053F79D23EC1457341DDD58D0651947";

        String KDH_priv = "00969A03C672D84D04B33DFC8E9AE6AC0AB9A6E84ADC9C8344D3DF4ACBB1DDF69A8756AF35B8D4F8FF847FC9AD32E25DC0E62BD82203D040CA4D1C19932337B959D6";
        String KDH_pub = "04019F603F9B98A50BAE8F35DBC70EA4F6C65776F640EE7A286A68BF2C0A5485BA4922C31F2332216D1BC48AB7D8096364C2AC9B6A4F41B3191B0EB3142602492EE62200B0210A52B1D58DD82E76696BA2E97DA7D416986FE8CEF03479396658831BB817CE8E42883A199CD184DCC2D13980EE0726244D950770AEF582B2D5DC6C94AC45A7";
        String KDH_nonce = "9E5E488FBC36E6F51A5CC0EBE7FCD55A";
        String KDH_pub_x = "019F603F9B98A50BAE8F35DBC70EA4F6C65776F640EE7A286A68BF2C0A5485BA4922C31F2332216D1BC48AB7D8096364C2AC9B6A4F41B3191B0EB3142602492EE622";
        String KDH_pub_y = "00B0210A52B1D58DD82E76696BA2E97DA7D416986FE8CEF03479396658831BB817CE8E42883A199CD184DCC2D13980EE0726244D950770AEF582B2D5DC6C94AC45A7";

        String SharedSecret = "00DB3A6678729EE8E980B815A4610B043CEF74EACD0F6699B47C01843813B57E9E86A13B96DD115D7BDE96DDCA8CBF749FDCF00895C19A2746C0A89886B37A1FF7C3";
        byte[] shareKey = AlgUtil.getShareKey(CertUtil.hex2ECPrivateKey(AlgUtil.ECCCurve.P_521, KRD_priv),
                CertUtil.hex2ECPublicKey(AlgUtil.ECCCurve.P_521, KDH_pub));
        PrintfUtil.d("ShareKey", "" + Bytes.toHexString(shareKey).equals(SharedSecret));

        String ExtractionResult = "7C791A27A940F61445795746DE4A2DD12C7DA801BC8EE63AA64D578B7B0CCAB8";
        byte[] extractionResult = AlgUtil.hmac(new SHA256Digest(), Bytes.fromHexString(KDH_pub_x), shareKey);
        PrintfUtil.d("extractionResult", "" + Bytes.toHexString(extractionResult).equals(ExtractionResult));

        String Context = "014B444B00019F603F9B98A50BAE8F35DBC70EA4F6C65776F640EE7A286A68BF2C0A5485BA4922C31F2332216D1BC48AB7D8096364C2AC9B6A4F41B3191B0EB3142602492EE622518F618D09A9A767545EA504ABB394349E5E488FBC36E6F51A5CC0EBE7FCD55A0100";
        byte[] context = Bytes.concat(new byte[]{0x01}, "KDK".getBytes(), new byte[]{0x00},
                Bytes.fromHexString(KDH_pub_x), Bytes.fromHexString(KRD_nonce),
                Bytes.fromHexString(KDH_nonce), new byte[]{0x01, 0x00});
        PrintfUtil.d("Context", "" + Bytes.toHexString(context).equals(Context));

        String KeyMaterial = "4DCE95F6095D394A882F16AF6B6F977D464F6BB24687C3C6D4C34E3AA0EFA202";
        byte[] keyMaterial = AlgUtil.hmac(new SHA256Digest(), extractionResult, context);
        PrintfUtil.d("KeyMaterial", "" + Bytes.toHexString(keyMaterial).equals(KeyMaterial));

        Context = "010000004B6579426C6F636B50726F74656374000004010000010000";
        context = Bytes.concat(new byte[]{0x01, 0x00, 0x00, 0x00}, "KeyBlockProtect".getBytes(),
                new byte[]{0x00}, new byte[]{0x00, 0x04, 0x01, 0x00},
                new byte[]{0x00, 0x01, 0x00, 0x00});
        PrintfUtil.d("Context", "" + Bytes.toHexString(context).equals(Context));

        String DerivedKey = "2A856D9437B104E2445A1FF09804EF7BDDB0124CC0C0097DF54894444258C200";
        byte[] derivedKey = AlgUtil.hmac(new SHA512Digest(), keyMaterial, context);
        derivedKey = Bytes.subBytes(derivedKey, 0, 32);
        PrintfUtil.d("DerivedKey", "" + Bytes.toHexString(derivedKey).equals(DerivedKey));

        byte[] ingenicKey = AlgUtil.ingenicECDH(shareKey, KDH_pub, Bytes.fromHexString(KRD_nonce), Bytes.fromHexString(KDH_nonce), AlgUtil.IngenicECDHDerivedKeyType.KeyBlockProtect,
                AlgUtil.IngenicECDHDerivedKeyAlgorithm.AES256);
        PrintfUtil.d("IngenicKey", "" + Bytes.toHexString(ingenicKey).equals(DerivedKey));
    }

}