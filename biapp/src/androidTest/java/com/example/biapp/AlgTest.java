package com.example.biapp;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.biapp.util.AlgUtil;
import com.biapp.util.CertUtil;
import com.biapp.util.PrintfUtil;

import org.junit.Test;
import org.junit.runner.RunWith;

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
        byte[] data = AlgUtil.getRandom(125);
        byte[] encrypt_DES = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.DES,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key8, iv8, data);
        byte[] encrypt_TDES = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.TDES,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key24, iv8, data);
        byte[] encrypt_AES = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.AES,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ZeroBytePadding, key32, iv16, data);
        byte[] encrypt_SM4 = AlgUtil.encrypt(AlgUtil.SymmetryAlgorithm.SM4,
                AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ISO9797_1Padding, key16, iv16, data);

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
                        AlgUtil.SymmetryModel.CBC, AlgUtil.SymmetryPadding.ISO9797_1Padding, key16,
                        iv16, encrypt_SM4)).equals(Bytes.toHexString(data)));
    }

    @Test
    public void hashTest() {
        byte[] data = AlgUtil.getRandom(125);
        PrintfUtil.d("MD2", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.MD2, data)));
        PrintfUtil.d("MD4", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.MD4, data)));
        PrintfUtil.d("MD5", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.MD5, data)));
        PrintfUtil.d("SHA1", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA1, data)));
        PrintfUtil.d("SHA224", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA224, data)));
        PrintfUtil.d("SHA256", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA256, data)));
        PrintfUtil.d("SHA384", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA384, data)));
        PrintfUtil.d("SHA512", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA512, data)));
        PrintfUtil.d("SHA3-224", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA3_224, data)));
        PrintfUtil.d("SHA3-256", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA3_256, data)));
        PrintfUtil.d("SHA3-384", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA3_384, data)));
        PrintfUtil.d("SHA3-256", Bytes.toHexString(AlgUtil.hash(AlgUtil.HashAlgorithm.SHA3_256, data)));
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
    public void rsaTest() {
        // KeyPair keyPair = AlgUtil.generateRSAKeyPair(1024,65535);
        // RSAPrivateCrtKey privateKey=(RSAPrivateCrtKey)keyPair.getPrivate();
        // PrintfUtil.d("PrivateKey",Bytes.toHexString(CertUtil.RSAPrivateCrtKey2Hex(privateKey)));
        // RSAPublicKey publicKey=(RSAPublicKey)keyPair.getPublic();
        // PrintfUtil.d("PublicKey",Bytes.toHexString(CertUtil.RSAPublicKey2Hex(publicKey)));

        String publicKeyHex = "00080000BCDDE53C4254AFBBDF3E196A8C8D0507F02AB8B25EB81FEEACD21966F6016A9F9B36EA0BE71E623C4E14A5719139971C1CC691FE132E0E6E466164ECA0ACB9517CDFEB752473FE81BF9C1A61A67FE309C00A5855409348B78F348E38198CB8F188C68C772E3F3699E4920CD780D09638F1334757EE9C4463799DBEBE2DFB9649EA2C74C53B2C9974DC28AA18C2408351B9A0C4CD95D8E6A40E4589DF59A230763C3CE80955F2F3E8E572B049E50A3F205B4F8D572E0EBB03B2ED17B8DF547962AA9C818209FE261B5631C930A7DD294AC35367793505EF5692420EB0D1FDD92E7C62101A8DA3ADE1D7C1F33985027366AEA708AED770EA58FFBD55CC0159108F00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
        RSAPublicKey rsaPublicKey = CertUtil.hex2RSAPublicKey(publicKeyHex);
        String privateKeyHex = "00080000BCDDE53C4254AFBBDF3E196A8C8D0507F02AB8B25EB81FEEACD21966F6016A9F9B36EA0BE71E623C4E14A5719139971C1CC691FE132E0E6E466164ECA0ACB9517CDFEB752473FE81BF9C1A61A67FE309C00A5855409348B78F348E38198CB8F188C68C772E3F3699E4920CD780D09638F1334757EE9C4463799DBEBE2DFB9649EA2C74C53B2C9974DC28AA18C2408351B9A0C4CD95D8E6A40E4589DF59A230763C3CE80955F2F3E8E572B049E50A3F205B4F8D572E0EBB03B2ED17B8DF547962AA9C818209FE261B5631C930A7DD294AC35367793505EF5692420EB0D1FDD92E7C62101A8DA3ADE1D7C1F33985027366AEA708AED770EA58FFBD55CC0159108F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000118D53033E920CB6E6F5EF1E6918E652FF3031AFFD0F672B46622C5D644D850D5A589E5E224C458F446EBEE08EDA85DD7036D947A8CB90C8AB15452F9CDF287F74FECFD3F8CC8779945C157B2A93ABD7665BAB67C971E067CA426ABE072738F49AACB3862DF40CE84138AA4879D574FB932F5A416CAB7DF42191685A2E9D6DF9EA485ED01EFD54528BBC3F327385968A707B7649948ED0FB84698E1BA378D7C59968DAE93EBC265F5AD963FFB3FA0DC3E931427CCCB3247DEF5E0E3C57949CA9E4A28FAB98D92BFB69CD84B308DB69977A0F4E463D68FAC81B4D2DBBBADD657DCE0972743362AC500A77338971993ABEB0B69479F0874CAFAA025B0E1247B0D91E106CDD008C9150914938A8CA5D784B856154238B7E78E89CBD6569F597620107F5E6EE1C3EA314190E08E24475EB816F1211ED149FF9533E560DE4CAEAEF675118B96D5454596EE88A33DD9A1176642AE757BC6180A0D7839B55E9916C62DD6AB021B611EA50E9BEE7492C71092917067A0D0486DC88C35DC8B45EF4B554D59D6DCF06E78F87281AD5BEFB613101B22DEACCDDF7ACB630E1966E6DDAFAB9B40F6147AD47EAF326A61ACAD146D17D1CCFA46D3812337BA5184C40EB0D0BD298FD802C75D778EF5645777AAE527E4A74E7A83BE9483C2C7B6ACC9655BFC28F8EF86DD4D2806BF4ECF2E8E960FD12290DD9C02E45844E22AFF0207FE5E60FB8827089BA505DF4029F0D5FBAAE22479F116C81C3A13475DB1432E2BFDD64CAACB21366E1B59C18FD4E088353EDABE6C2E289A82C4D606B9A3308006CB9A2D587E0F0E63C39A56F3098A086A0E34A407EC1E82E3F59F274E4323A5397DEBE7461F7CC5BFE7E23834E2312ED700C262ACE8A95F1D74BA4090DA6439128ED34F936CC91CB332626F42307965E0ABEA542D889265D00B47D8AD263411EC8ED5F9CB2057D306F549410AC1DF37E0CAD5B9A4BEDF7466D585A060A740904D67F0F250F22646A2486311BF44C3FC72FD9ED26F5671C327A9E3489E51F2F2AD8C1E775639BA34F78680DC35DD9F0B06FCC06C1D03E0B62024C42D9F5042F3D08187B5C8A36DB79E5B053FC7C4A701BB57A488C50A82CC706067E2FA18A733841669854E789FA628C0B4EC5B53FDA6648C7D1A5C3C338B6274E1F51B9D5F914E5873A5A1313470FE1B307AB75C1BA922EEE00412B0C333A12AE5C799FA33BBAE0BCCFA48E9623B99AC6C415CA40A29EF287CC1DFFD6F90FF7A2BA761CD79C14B1BDEA53D1875";
        RSAPrivateCrtKey rsaPrivateKey = CertUtil.hex2RSAPrivateKey(privateKeyHex);
        String data = "1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz1234567890abcdefghijklmnopqrszuvwxyz12abcdefghijklmnopqrszuvwxyz";
        String signHex = "4336354FCC76BD3E0A5C533EA569E9EDC133CA5895579A74D00E9140B2ACDECA3762CE01BBFC56C2B98AE1E8DDB0F1235CBB5239DD2D56E8320301362BB5D92310DCA23CB246772C6CB0FBFBC571D1107FB5EAF0E698E52B7002AAE70E55B9A3254154EB204F3E17D67D503056BBDBA4CD3F2AB131102BDFBE5EBE5D2766579E7F33489BABDDB54D766AF0A0B8039CCA7E77E7D1662D34C06D5E08D46961562B29597DE01AF23DAA296EA7E5AA631557B22FDBD643BAD0A632D83B0B097C15B03E33382AB0865C0A13D57C1AC39673AA48C558C448EF8498950ACBC0209DD73C82B4CEB7C8C3D34EFD70F0BC2CD9EF55883DBA5B14BD9066066ED800453890B4";

        PrintfUtil.d("Check-PublicKey", Bytes.toHexString(AlgUtil.encrypt(AlgUtil.AsymmetricModel.NONE, AlgUtil.AsymmetricPadding.NoPadding, rsaPublicKey, data.getBytes())).equals(signHex) + "");
        PrintfUtil.d("Check-PrivateKey", Strings.decode(AlgUtil.decrypt(AlgUtil.AsymmetricModel.NONE, AlgUtil.AsymmetricPadding.NoPadding, rsaPrivateKey, Bytes.fromHexString(signHex))).equals(data) + "");
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

}