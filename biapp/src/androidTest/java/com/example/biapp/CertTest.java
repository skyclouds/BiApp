package com.example.biapp;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.biapp.utils.AlgUtil;
import com.biapp.utils.CertUtil;
import com.biapp.utils.FileUtil;
import com.biapp.utils.PrintfUtil;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

import aura.data.Bytes;


@RunWith(AndroidJUnit4.class)
public class CertTest {

    private static byte[] KDH_ENC = Bytes.fromHexString(
            "3082042130820209A003020102020160300D06092A864886F70D010105050030333111300F060355040A0C08496E67656E69636F311E301C06035504030C15546573742056332053657276657220537562204341301E170D3138303430393133313035335A170D3238303430383133313035335A30163114301206035504030C0B4B65794D61737320456E6330820122300D06092A864886F70D01010105000382010F003082010A0282010100C4F40B6B2CDE7ACD9FBDD12E444377FDE40F3320C35740471890EC8F7FA2DFEC7E6BFC91E862FD3C5EB9233CBDB72A69B194ABBC8A0C006AC27CB5E35611383DCCCA0439B51AA6169C3A8A7AB69C79B0A75E35B14E567A79FEAAB3F2EDB1F0ED425A073D3E310C66E7FEB5A49113FD8691A8F4560D18E81177D57203BE2C23995E1EED52E4F74613A1610313BE57698C81AB215C5F76FBC5C08F64832B54077CF30FB899B925A9EF596D2183271EF21304937F8840751CD534B135BFA39884B6D9C0B53A6688217EBE89418D7DC1FE5F7B53D19C1852F37CB573B19C7206ECD3962CF1DE8D381592B8186B5EBCF4F5C9FFBFF7B22355E71B165D12EAFB9CBFA10203010001A35D305B300C0603551D130101FF04023000301D0603551D0E041604143293F7BD62F54C39857229ED1B0CE561537770B4301F0603551D230418301680146F375386657D48097180D585255EC0A125375CA7300B0603551D0F040403020520300D06092A864886F70D01010505000382020100C3286A9B269DA6899A049CC7F4C614595EA4C955D3975B545737ACF77E58950D16589A356C783150A2ADD18E4B79C646D1AB54175239B7247FDC7B756682810A4916C390FEBB7C1A5DFCD89E684AEE3F96B6D5C105E244F7C0E5307886B6370F29A6E62172382861C99E7D1F034367A0575A3EA9FD25BBAE1DE284817F85150F986E4A0F7EB6D6D66CA4EC7F413F45D23ADC00EECE42631D2F1B61A86FAE66253CD417F68562ECE395A8BE47D33E556258E688EAA96CA6340DC8D14E2712171B126E6A7D00D152E7B364791EDDB0D1280CF6DA8BFC9AFAB78D264A01F6054A0258381E68308F83FF63FD5432A128009D492F2961B04E855DDCA283C9E19396A5EAA0D79CF25264715F4929FB48638AA65266181739D51F88E90C63BF9EA0DEFAEFD024705E323B38004D881897F617CB3452DEA2D195EB469D272976643142BA22A1ED51B3F7EEC5523A5F3BC0F1F8BE83B03D76926DE0E31FE03ADB0F2B95F1E21C6DC2353F4B6667E4CDADDA306436AA97DE2037755EA1B9438B86CF9005339F2F7AFE09962ABB991EA82367479FAD886446E4296634869B078F7C3D2C218A5EC2C41DD15FDEDC9DE60CFD2D3A680C7E9BDC6A98AAFF32BC714E505149EBC7FE635B6A5C7B1A61C260835F12FEA80994D35BE60ABF2B3A175D2491BFB8957E96576C1FB8E123121B80E647C2B1EA2FB4F87DC69D1CDCC52DE1A03FDB5FDBF7");
    private static byte[] KDH_SIGN = Bytes.fromHexString(
            "308204223082020AA003020102020161300D06092A864886F70D010105050030333111300F060355040A0C08496E67656E69636F311E301C06035504030C15546573742056332053657276657220537562204341301E170D3138303430393133313234375A170D3238303430383133313234375A30173115301306035504030C0C4B65794D617373205369676E30820122300D06092A864886F70D01010105000382010F003082010A0282010100B28E56EF9BF39895A54A12D53C5C7A808B1CEE621B43091EB8073AB8D2FD1FBDA95D9BC4D55314D6E6A5D0CF82AD7598BDCCEA908717453F3B70BA6391CE1D7A3DB604FA40D54D7698D53EAB71EAFCF8132CFFB1E8F4D8EE50B3BA9BE51C00AA3F4443ED5665C98A962C94C28A70F16E721E21F40C45608E0B99BCDD47AEC07B8235D2F6D892BC8D80962345A701AC93F3BBDEB3B000171CB08C44E0923B2F2C7ADAFBE8FEDB0D32AFB2BD3F6989BD340994CEAF5A676411BC19E41FB0A563D9C01A5BD54E86CBFA3B64DE8ED996F89A638932EAC3CDBBC9200832AB5E648F52CA094091519285C2D83DE3DA1C56645262D7EF1B61A20C2E109C8C2B7615E9830203010001A35D305B300C0603551D130101FF04023000301D0603551D0E04160414AA3D41438613704FBF6ECAD6230490631F6F82D5301F0603551D230418301680146F375386657D48097180D585255EC0A125375CA7300B0603551D0F0404030206C0300D06092A864886F70D0101050500038202010084D3E5FA596DC249DA72B928AA1F9B86C743B61B8D56F10B680B9E58D1E6AFEA0F92DE1DB9F898D06B802454742BFBA266012CE75B2C272D10363A902E0A908D443250AC706077B66F63FF7D906F71F2135EE2972EAFEC4D03F127AA29D2D466BBEFFDD037FCB998E8EE4051B8F24B08512079126ABF03449283BC925D67DA2E54B7632E80E80094D53E40D0286EEC6A54FAA46673EEBF68B63269A67ED6357BF08F1CD137EF0E4DACC417460CEC40133F70E6DB5F391B4AD322FDBA09DC765802B9193661230EFCFB3B4F78E67445FE9460DF333542A10CCD95ECFC1E2F3CFF8F96BFF275996320A5E97DEDBEEE9DD7A5052E7AAE3DBA78D081CB39E55F016856441F34DFD0DBCE9774DC40F45F0F36BB790D68E197CCB12190CCA09466D0F9472BF569FBA6BA593E508D01D0AAF9023C7A7B7151F67092AEF438B59E8DED345DD84810CEF1A6387F671C572B526CAE2247BBA0443097CBA6FCA2BA0D03E6F18B53BEB11EE385F4E59576C82911934FA24136B317D4DB55A2AF9872F35F103656B0BA8834EAECF166CC8FC3666162D1318B3A6D720AE4A16C13D1D4DF3099E165B7868286E1D3108BFF2D15C4FCEBB444D9AE55DD37A41C42FE69F653A0F3B70EFF8A031CB36BA74843CCE2A5D1F0A4CAE1F12AC9C36264C6F044C07C4D90470B79DCA4D785AB36CA917EDE39E1DCF0B8C0271F978BD0D97CCDFCD38B88EAEF");
    private static byte[] KDH = Bytes.fromHexString(
            "308205423082032AA003020102020100300D06092A864886F70D01010B05003031311C301A06035504030C13546573742056332053657276657220526F6F743111300F060355040A0C08496E67656E69636F301E170D3136303331313038353331315A170D3331303331323038353331315A30333111300F060355040A0C08496E67656E69636F311E301C06035504030C1554657374205633205365727665722053756220434130820222300D06092A864886F70D01010105000382020F003082020A0282020100E71AC300BF2B6067559788165EE90541D79BDE2D2B40AE568780F1BEE6000A4C50D7D79CBFE74EDF1C926385971F69B573306EC5C4F2D59FB112720B4F7A5788F534EBA2704CBD867D021CDAC6D2F7899BC17E5A536076AF014811B8B7FE441A806EF540A7055D1CACB3363B9968DF9CF600F0C784EDC3754F2714D21A6B03442ED41B3134E682FFB508F36F0CF57DED2EAA4357C01EEA681971CD51A39E774FA2C2445502ACDB54A91D9E14EB1A6BB4B68D35165F472ED0C43CC43914427381EED69A8D73C5FE85E95E308BBE1DB8D50DBA34317615C28C8050A161F5B1DAA2647D60E5531CA1B7F1D149A3065430C93BB986F44D2AE3EF7068D54A2E3BD901F8AC40D2D2EE453FEE274590E6AF057D84D083A81F62B8E37F0F7E1E332B5E6B90B69846E2B1F1A2FDDED19F5AD3A6A01D7E108C7CCDEBDEE6AD97690FE83FF558B60F87705D3E3FD0E2DFBB81021539855CAA2E25F70548AF9F5A94C8CC8176294AFF1D3A8DFF89098B4A7DAA07A646884898B230A1529D490A0EF1F9A87D78879D695054467D0D12AC9E282E017909068C37E7E6EB10F627466293AB68CD30663CA6BA72460C0575FB4BA2B321FB41B93618B6460F705D6D9E72EFFB84F8DDCD17003ED525C31245C56F1760242D6905C471383D686EF60786AE5C1003C3703F37DD2B75E860A83CC2262C19C0D83BC84C32E2EFD27CA2801A3D6B8AE71C130203010001A3633061300F0603551D130101FF040530030101FF300E0603551D0F0101FF040403020106301D0603551D0E041604146F375386657D48097180D585255EC0A125375CA7301F0603551D230418301680147B88065F048BE465583FBDB4308924E5153B14A1300D06092A864886F70D01010B050003820201007CB00F1724C105113A09BF28F49850C525C18B3332BEA5A4AA101528CA92DE0A12D25AC4612CA515DF54229B6A97A3395C9A483E1FF9603B5EF57664BAB06B2F74F4F4F39B71F65EAE952E0DC171A020C5BA1A211D5CB76CD64942B600609AB058AC2E17AC3F77C760C53146DACC4270996558AE490D92D9E539A8D674CAF4A59D73ABAC285A90586FD70D443E536BA5104EF010DF58EF5BFB530F4C6BDC485AC6C0F2F1F002DB01F5D8CB9BA831CF090738881CD25FF5AED275841F04E7B124503F425B319DF9F262555030AA4F0B5FC536CCB49BA0140E6F2A33C8711964933AA05858A3177E1F7A8DF851CD79125D9802F8A4305EC0AB831D857EFFB3AECF3550D21462DE741BE80B944BEC402638D8B81286691500BF899229F11544BAC85F61CABE15E6F10726E8D1A58557AC51AF5E4C2343314B4A50CCEABDF3E567750491DDDD06AF567FA98C7AB397A140C71744534BBE3EEA6EA6B529A851BFA309EA7E64D713E60972BE288EC7AE89C2F1BDDDA7B5370B8732A6763FDBA385276C26299E60AE88AA5EF774AAF72E69493FA10CFFE50627E477110E945FC2813C72F000BF09244E9FFB54C93E6916DC11EDE2158A1A9249E4BBBF19FDFE6A8619729FEBC57A3A0C136B65761EF04B05A6D932BC246996F9BF3616E66B7193CF9B1F6BBCE72A91427E0AD7C85469D279AD24543ECFE2C29A20116F84D600AD5D8288");

    private static String publicKeyHex = "00080000BCDDE53C4254AFBBDF3E196A8C8D0507F02AB8B25EB81FEEACD21966F6016A9F9B36EA0BE71E623C4E14A5719139971C1CC691FE132E0E6E466164ECA0ACB9517CDFEB752473FE81BF9C1A61A67FE309C00A5855409348B78F348E38198CB8F188C68C772E3F3699E4920CD780D09638F1334757EE9C4463799DBEBE2DFB9649EA2C74C53B2C9974DC28AA18C2408351B9A0C4CD95D8E6A40E4589DF59A230763C3CE80955F2F3E8E572B049E50A3F205B4F8D572E0EBB03B2ED17B8DF547962AA9C818209FE261B5631C930A7DD294AC35367793505EF5692420EB0D1FDD92E7C62101A8DA3ADE1D7C1F33985027366AEA708AED770EA58FFBD55CC0159108F00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
    private static String privateKeyHex = "00080000BCDDE53C4254AFBBDF3E196A8C8D0507F02AB8B25EB81FEEACD21966F6016A9F9B36EA0BE71E623C4E14A5719139971C1CC691FE132E0E6E466164ECA0ACB9517CDFEB752473FE81BF9C1A61A67FE309C00A5855409348B78F348E38198CB8F188C68C772E3F3699E4920CD780D09638F1334757EE9C4463799DBEBE2DFB9649EA2C74C53B2C9974DC28AA18C2408351B9A0C4CD95D8E6A40E4589DF59A230763C3CE80955F2F3E8E572B049E50A3F205B4F8D572E0EBB03B2ED17B8DF547962AA9C818209FE261B5631C930A7DD294AC35367793505EF5692420EB0D1FDD92E7C62101A8DA3ADE1D7C1F33985027366AEA708AED770EA58FFBD55CC0159108F0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000118D53033E920CB6E6F5EF1E6918E652FF3031AFFD0F672B46622C5D644D850D5A589E5E224C458F446EBEE08EDA85DD7036D947A8CB90C8AB15452F9CDF287F74FECFD3F8CC8779945C157B2A93ABD7665BAB67C971E067CA426ABE072738F49AACB3862DF40CE84138AA4879D574FB932F5A416CAB7DF42191685A2E9D6DF9EA485ED01EFD54528BBC3F327385968A707B7649948ED0FB84698E1BA378D7C59968DAE93EBC265F5AD963FFB3FA0DC3E931427CCCB3247DEF5E0E3C57949CA9E4A28FAB98D92BFB69CD84B308DB69977A0F4E463D68FAC81B4D2DBBBADD657DCE0972743362AC500A77338971993ABEB0B69479F0874CAFAA025B0E1247B0D91E106CDD008C9150914938A8CA5D784B856154238B7E78E89CBD6569F597620107F5E6EE1C3EA314190E08E24475EB816F1211ED149FF9533E560DE4CAEAEF675118B96D5454596EE88A33DD9A1176642AE757BC6180A0D7839B55E9916C62DD6AB021B611EA50E9BEE7492C71092917067A0D0486DC88C35DC8B45EF4B554D59D6DCF06E78F87281AD5BEFB613101B22DEACCDDF7ACB630E1966E6DDAFAB9B40F6147AD47EAF326A61ACAD146D17D1CCFA46D3812337BA5184C40EB0D0BD298FD802C75D778EF5645777AAE527E4A74E7A83BE9483C2C7B6ACC9655BFC28F8EF86DD4D2806BF4ECF2E8E960FD12290DD9C02E45844E22AFF0207FE5E60FB8827089BA505DF4029F0D5FBAAE22479F116C81C3A13475DB1432E2BFDD64CAACB21366E1B59C18FD4E088353EDABE6C2E289A82C4D606B9A3308006CB9A2D587E0F0E63C39A56F3098A086A0E34A407EC1E82E3F59F274E4323A5397DEBE7461F7CC5BFE7E23834E2312ED700C262ACE8A95F1D74BA4090DA6439128ED34F936CC91CB332626F42307965E0ABEA542D889265D00B47D8AD263411EC8ED5F9CB2057D306F549410AC1DF37E0CAD5B9A4BEDF7466D585A060A740904D67F0F250F22646A2486311BF44C3FC72FD9ED26F5671C327A9E3489E51F2F2AD8C1E775639BA34F78680DC35DD9F0B06FCC06C1D03E0B62024C42D9F5042F3D08187B5C8A36DB79E5B053FC7C4A701BB57A488C50A82CC706067E2FA18A733841669854E789FA628C0B4EC5B53FDA6648C7D1A5C3C338B6274E1F51B9D5F914E5873A5A1313470FE1B307AB75C1BA922EEE00412B0C333A12AE5C799FA33BBAE0BCCFA48E9623B99AC6C415CA40A29EF287CC1DFFD6F90FF7A2BA761CD79C14B1BDEA53D1875";


    @Test
    public void certInfoTest() {
        X509Certificate cert = CertUtil.getCertificate(KDH_ENC);
        PrintfUtil.hex("证书", Bytes.toHexString(KDH_ENC));
        PrintfUtil.d("证书拥有者", cert.getSubjectDN().getName());
        PrintfUtil.d("证书颁发者", cert.getIssuerDN().getName());
        PrintfUtil.d("证书签名算法", cert.getSigAlgName());
        PrintfUtil.d("证书版本", cert.getVersion() + "");
        PrintfUtil.d("证书序列号", cert.getSerialNumber().toString());
    }

    @Test
    public void verifyChainTest() {
        X509Certificate rootCert = CertUtil.getCertificate(KDH);
        ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
        X509Certificate encCert = CertUtil.getCertificate(KDH_ENC);
        certs.add(encCert);
        boolean verify = CertUtil.verifyChain(rootCert, certs);
        PrintfUtil.d("verify", verify + "");
    }

    @Test
    public void pemTest() {
        String pem_pkcs1_publickey = CertUtil.publicKey2PEMByPKCS1(CertUtil.hex2RSAPublicKey(publicKeyHex));
        PrintfUtil.d("pem-pkcs1-publicKey", pem_pkcs1_publickey);
        boolean check_pkcs1_publicKey = Bytes.equals(CertUtil.publicKey2PKCS1(CertUtil.pem2RSAPublicKey(pem_pkcs1_publickey)), CertUtil.publicKey2PKCS1(CertUtil.hex2RSAPublicKey(publicKeyHex)));
        PrintfUtil.d("check_pkcs1_publicKey", check_pkcs1_publicKey + "");

        String pem_pkcs1_privateKey = CertUtil.privateKey2PEMByPKCS1(CertUtil.hex2RSAPrivateKey(privateKeyHex));
        PrintfUtil.d("pem-pkcs1-privateKey", pem_pkcs1_privateKey);
        boolean check_pkcs1_privateKey = Bytes.equals(CertUtil.privateKey2PKCS1(CertUtil.pem2RSAPrivateKey(pem_pkcs1_privateKey)), CertUtil.privateKey2PKCS1(CertUtil.hex2RSAPrivateKey(privateKeyHex)));
        PrintfUtil.d("check_pkcs1_privateKey", check_pkcs1_privateKey + "");

        String pem_pkcs8_publicKey = CertUtil.publicKey2PEMByPKCS8(CertUtil.hex2RSAPublicKey(publicKeyHex));
        PrintfUtil.d("pem-pkcs8-publicKey", pem_pkcs8_publicKey);
        boolean check_pkcs8_publicKey = Bytes.equals(CertUtil.publicKey2PKCS8(CertUtil.pem2RSAPublicKey(pem_pkcs8_publicKey)), CertUtil.publicKey2PKCS8(CertUtil.hex2RSAPublicKey(publicKeyHex)));
        PrintfUtil.d("check_pkcs8_publicKey", check_pkcs8_publicKey + "");

        String pem_pkcs8_privateKey = CertUtil.privateKey2PEMByPKCS8(CertUtil.hex2RSAPrivateKey(privateKeyHex));
        PrintfUtil.d("pem-pkcs8-privateKey", pem_pkcs8_privateKey);
        boolean check_pkcs8_privatekey = Bytes.equals(CertUtil.privateKey2PKCS8(CertUtil.pem2RSAPrivateKey(pem_pkcs8_privateKey)), CertUtil.privateKey2PKCS8(CertUtil.hex2RSAPrivateKey(privateKeyHex)));
        PrintfUtil.d("check_pkcs8_privatekey", check_pkcs8_privatekey + "");
    }

    @Test
    public void rsaTest(){
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        X509Certificate cert=CertUtil.pem2Cert(FileUtil.readString(FileUtil.readAssetsFile(context,"apos_enc.crt"),"UTF-8"));
        RSAPublicKey publicKey=(RSAPublicKey)cert.getPublicKey();
        RSAPrivateCrtKey privateKey=CertUtil.pem2RSAPrivateKey(FileUtil.readString(FileUtil.readAssetsFile(context,"apos_enc.key"),"UTF-8"));
        byte[] data ="1234567890abcdefghijklmnopqrstuvwxyz".getBytes();
        byte[] sign=CertUtil.sign(privateKey,data,"SHA256withRSA");
        PrintfUtil.d("sign", Bytes.toHexString(sign));
        boolean verify=CertUtil.verifySign(publicKey,data,sign,"SHA256withRSA");
        PrintfUtil.d("verify", verify+"");
        byte[] encrypt= AlgUtil.encrypt(publicKey, AlgUtil.AsymmetricPadding.OAEPWITHSHA256AndMGF1Padding,data);
        PrintfUtil.d("encrypt", Bytes.toHexString(encrypt));
        PrintfUtil.d("decrypt",Bytes.equals(data, AlgUtil.decrypt(privateKey,AlgUtil.AsymmetricPadding.OAEPWITHSHA256AndMGF1Padding,encrypt))+"");
    }

}