// Fixed-width bignum / Montgomery modexp tests.
//
// Known-answer vectors (kKat*, kRed*, kMul*) were generated independently of this C++ code with
// PowerShell 5.1 + .NET System.Numerics.BigInteger::ModPow / Remainder. Inputs are deterministic
// SHA-512 streams: concat(SHA512(ASCII("<label>-0")), SHA512("<label>-1"), ...) truncated.

#include "carplay/bigint.hpp"
#include "carplay/srp6a.hpp"
#include "test_support.hpp"

#include <string>
#include <vector>

using carplay::bigint::Modulus;
using carplay::bigint::Number;
using test_support::bytesToHex;
using test_support::hexToBytes;

namespace bi = carplay::bigint;

namespace {

// KAT0: mod = RFC5054 N, base 384 B (may exceed N), exp 64 B
const char* const kKat0Mod =
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404dd"
    "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f"
    "83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa0510"
    "15728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200c"
    "bbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff";
const char* const kKat0Base =
    "bfdf65797b3808098a286f9493bc01ac5319eb291ca7e5f98977088d2497ec6c3642f1bfe0dea157ad7304e900dc442c"
    "488a18dbc9ab53c7f4c57fb8c3b3aff048d22e428ece8b413a0a5c226558d7acafff870cf703aba2848ba6c62fc20c9b"
    "d574201c14a2831c27fa1c6b16ad6e18b9d9d080f208ab757f52f4c403d23a4d4627b4066cab5c0d543432710aaab61c"
    "2f5ce8284b0e6ad8cbd6f41d8133df8707c12f3fcb77e8cfcfeb9e8dfcfd224ee88d8a693f5badbceef0830262cd862f"
    "d82bfad88d80f22933e90da2a479aa5c8ccaa1703ec93297cecb8f208864a3517891f570a411b84f19b541913c87ab45"
    "7789ed65e14b0b81c9c34c9eee6c642638d8b3122d64291af489dd24ce2cca340ed89c6caa9e9b993cbf8d98a3d89656"
    "abc93bdeb43da60b8ecb9185c1f76db4a8c049641eecd94765b32b706d976541563c1939c047b911f43343d22d29a5a0"
    "e4ae1e5db573684578602b9425e94e587f2cdc53fb63189b8e192422356ff351dd4f98f2c405d7887e86e644be5e8dd2";
const char* const kKat0Exp =
    "82a72673639928db6767a5e02393c9dc320e7bbb6c483655cc7330a79925e19e2ba407c3a72d4e10099adbd85ccd63c0"
    "56700a1ccae13a84c0e7275782ca7ae1";
const char* const kKat0Result =
    "39bcb5b00f256616356a27c49f4561bcf3199c7180a93dd8a5904186031726fa8f53173b99d4666ee50ad5e4fafe0a93"
    "0f41d8c58ac3c08611a53ab0b9adaca8f65e45cd470fec91385efaaaaa8b9930fafe9456f5901a26eb42e4aee9d5d937"
    "4992d3e76a21a62af1942a592f7f64a6e5c43e6ba01381b6c08e9cf0bb80aa12e29549b524bb5fe2e4cfc71d9cf25b12"
    "77158a81c68873a695671ecaefbe4b1b103d40f014f85f3b28836d68d32686b750f38be887a2df0b71c3642b8c2c41c8"
    "652378bbf97bea0c5a23e1314fcfd28895366f442c4d49d363cc29b1fb5ab540f2ec0fa3ac5bf40da6ae8e5fa5922505"
    "27458aef91b20b4f3775121edb7f5aa6b9de56e35da5d949300820e81277b04419a6a945f4d39f4a97588718a7200d99"
    "a93e0bec7c3500408e47e2d061cecd3e390e65a63da763a96e08562a0282a9320a8531d561bdcbb755e8582c8f3c4b82"
    "6ed60c854e2b635eb0eb75899542e94edcd07b5e3725505147b0f3374c4613dc99b62dac94fd53c29a5a22d9717905cd";
// KAT1: odd 2048-bit modulus, base 384 B (> mod), exp 256 B
const char* const kKat1Mod =
    "8122d90b5857183791981650ae229b75342fbe558a42548c104ff3abea9b73b9b63a3588f4600eb1e7c3c6315b754121"
    "15c06204b824899152fb3284733297b1370d5ea28ccce99b859bc62214e0bf90db6817fc9e6ef601c65b4331d01e6c2f"
    "e8800776f3b8842b343a1ba2a20487544ab1076c1f037079223c0f498cdb733ecf74be3af17dd96d7c3264ce2dd280f3"
    "5b7b1a2042a4c734ff2b3d0ac74a0618e43dd0f0e7e8128af0a8c2cca51665bac6650c3c11a26d7b8fde359fff6279f0"
    "5afcaddc46c000b4c6e9e0108e62dde619d2769a290183d74c04de80686ea6d6a3fd576be72f1c10c595cd9eaafb0a84"
    "8c00380a5ba29652fb1c7b53ef77853f";
const char* const kKat1Base =
    "75f2368b50c300c4f3d1249fdad3be549ef5c331a241c624c6f77efd91112d4c6cd32143873d6f505c48430219cd227e"
    "a10b3829ed04cbe1860b20cc0306a7f11ef69b5afd181ee1b9e2eab977f8d864c1bbe4a0974a6b71c2d527a199a1356e"
    "31a2d4209ae26167ca6aaa3637186de991a4659e55fd92424f4a47991bd009d6c62f9ba55dea751bc985462998bb8c16"
    "766bcc529a55ca6c4e9101584253c438ced0f6ea5bc3d1378db20cb040f4d69c2476c58e1397259fdab117fcdfe9e897"
    "3e5e8c44dcc1a25a5bdf042bf13c83a669a50c07561cd5769153a63a9139e8599424cf2f825b43ec31a6101d36210c40"
    "7853e62e6773d9111402dac9f5f08cb6b44ea889972b3d5f5ce2a75a9384560cd8ce97e38f30eb61d551ebc0d9081ef6"
    "76891a721f59b78eec67f946478cd1b3d86eef3e493e7dc43bae9088694eee5edd544ee9b365dbb8ccd6800f4ac9e954"
    "deadbeea9fe2a05665930af734c4346ae1e4fab81b82397932899e9f23a2099632077cfc21ed9e5a0550e657d88b50d8";
const char* const kKat1Exp =
    "0ca3ef191c26a092b743c7154f2a26ddf050e9f70ba8ce9bda28daf2479168c814a01eb5373df5358afeca38b7303b00"
    "b6e6d0d2ef7747ef3aae03c643473d99cf3d707926bce628fb3415acbe882c7d9417616813241481f3f213f03f0c54f1"
    "3ccec1c3b77b0ffd51f4392a62e8ab421196dcf7f922caa23c7bbf8350d512704512c4e004e67029f786a29482fd4a5b"
    "f2effdefe6e5a95fd7cfad9d80bb0e97fd4a247ca8add6596415ce4b3784c537dfdbc72ae48e5b81a31af3330296146c"
    "0acbb699a309e876688852505f10a73f5944225d7bb913dbd9b85c7f1bb48940d2074580bc28ab25ea96e8b61322de52"
    "3852b8a1ef90ab91bd2a363c06f80262";
const char* const kKat1Result =
    "48fa77d55bd482c20f6c1216452abe32f09d338a6ab26d69cb0983736a03a24a285024349e50557e0e9be5df493db474"
    "9077b15768e89efae9b54a954dcc80bda86c563efbb2e5f14c594b5664bc8ca5e1ce6d2a537d129b5035983730ffefb9"
    "dab9330e52dbf23e95570b0d7ca7971e79f01d401cb560271899b94b9ac1954d0dbaf7fba17e5fa82d5ac04d53f47ffd"
    "008165ba8d2d740be5f266bf02034fcfb3bfcfb3088dbb2de110ac3cd588f551536e83ceec1f15793b3fd8606b4a06b1"
    "31d77c3d90465993d3e8ea69f9e23bc922c83326305eca34d3186c7cb87100cd178d5ab786f9787fd6d24f769a09de26"
    "0b34bfa8c72edb57da9a676986f07c4c";
// KAT2: odd 1000-bit modulus, base 100 B, exp 33 B
const char* const kKat2Mod =
    "9dd7402489a824e6742d217eac74352f55ac2cae53cc8604fcce0e909ec0a813f8a2fd97f81ee1a3077ba7e3038b4ac1"
    "602b7987103218bf885e825619807a8c5cab42e6a22a0972cce26c3785d71c63eb7a920d87273d33163640234a92c1af"
    "3b170ee214cb20928f0eb34d1dfefc841883b3f95f68e493397c5c8bef";
const char* const kKat2Base =
    "e59e000db429166c71905ef3e5ae72d31aff6c8f6bed932fb5e2c12a444635d1494d00d70d82b799ae9499b1b2e2f10f"
    "39ff9e3b3d1cf1dd6e6f4c60de7b0a80e8c3bbffff62fd26c962771159c527c38891bfffd9f156ede32be13ac19b3683"
    "2979490b";
const char* const kKat2Exp =
    "6e25a98c2834923866a93d4ff42c78842efc57271aac05a16bcf4a11cf501b25da";
const char* const kKat2Result =
    "177b783809f247acca8133403f814d8ca30c8b7d140f786f3ea5440cdadf94172894ed8a04611176efcfbebc946f57f5"
    "efd62d556d42ba219ab84001b20875bf8a1c9285741f74ab532d1a491d9cbff360f7f2ebc53ad523f4606df4a0ac0cb7"
    "9c68611b5d75eb8094f1da90b22490bb6243367af4c5313227de94872e";
// KAT3: mod = N - 2 (odd composite), base 5, exp 32 B
const char* const kKat3Mod =
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404dd"
    "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f"
    "83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa0510"
    "15728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200c"
    "bbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2cafffffffffffffffd";
const char* const kKat3Base =
    "05";
const char* const kKat3Exp =
    "7ce73f7556d82ca0fbab72843c91457e493a94fb3431df4a6433b2b64e55ceab";
const char* const kKat3Result =
    "c948b158aedb595c658aa489055c7f89e63891b348343a18e2f062d1b23e18c4e5e7a1088fe2002e296a8c3665faf96e"
    "eb120d2c351303d95bdc4dafaf935e1aec5661a5692e78c7c45bba6685de75a32cf0bd5f4039f2c4f014df8598c62ffe"
    "3b67710e0b8b2414d04dce72a92d251500cd822d0b8aea55249c0aa3f7f4f1349eddc63b850806730ab02653111d0513"
    "3de8342a59f49480298907cd48e72da5fc4f8643e9554a7c6f7311aa5256803cca953baa15ca1ca64fb51adc7544d2b1"
    "26be458de1e3f04e13d999f1c1b62f88aa15f6d51c5f8674e51ba844658e06d635644221dbbb2ae1e2551fcafdad8adf"
    "741c39697ce962ee4031c6f2a3199251e3d148c54e6a57376d4487e073870acd4a3a69afe4e5967af3b2b6c65ba76332"
    "d1e0c8430ed33e09321fb3191ec4861c7c243598e18e54f1f1c627e689e36930de7bd13e15571d61396ba1eb9d123e57"
    "41c708d09419b5af7a1dd72dea8b2432a8725118b4c3fe8e7b509890d38addfbe75680eb79a0a4ccd768491bf6bec9d0";
// KAT4: mod = N, base 200 B, exp 384 B
const char* const kKat4Mod =
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404dd"
    "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f"
    "83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa0510"
    "15728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7"
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200c"
    "bbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff";
const char* const kKat4Base =
    "cdb35bcd525ccddc73b1ee6930c85681ce94d2d1c654ca229da5f6ab030d903ac9ba7a92551dc8ccb6b177b556978308"
    "ea33c3d48449b6835d7cd76337d6c7d41124b26dac474b85bd17415a57b39c07cea53a1858b006d5840edd73a9c68719"
    "e9fe1a08291906b37159ae25d4b65d38e76371ae5191e13a54ad4fbdaf9a2a15d672da84e1122d91e113d68b2e164e0d"
    "4eeb85a2917506be6008ea54fb506673bf7b44b4dd43fe71b7cc97064f3f0b61c7dc08e88b39f1d4009150aad29e6612"
    "aacfd59b281c111b";
const char* const kKat4Exp =
    "35c955c4164872731ce29ee3148b0b6e5ffa199b1fbe9b6c77b477234adacdf3056380df917fa0b1baaed5d873da7e52"
    "546c8c6005804d3b7f76c5ed42da031ef410fcb0b46a991842199336efbc456461ec441c1521c4c0bbbe3bf315e67425"
    "5de3efde7185c03e23f77c4afbf7c949e11b79798b64f102408df5e059643dd04633779967d9591acee5b13ada7c6fc4"
    "07e58708b4fb536d15f4a5c0395363e8601fbf4f151966b09338979922752929a52b089256d9b9c1fee96388a4bef7bb"
    "24e8130eb8e125c525ed3d20b1e2999fa829acb28dd94a4efd07cccb820fd44cb39e05452f97be2c4ba3dda659231b91"
    "05658912b7d20c7c22f4add7050476fad22c654234820bd6676953f82d21392537bc67359070e7d0b07a30712b661a68"
    "3147c88bcf4603edbd0337b6c803d3ea3b4cac24a745754854a09d7a4dffddb3018901ebfd372c73753ebd968d7d8ace"
    "e5453759fc67b13888f7cef1c73a03685df1844a51937b1d94fd580aec50d4dca93edd030ccabd31cd84e73c626b7d49";
const char* const kKat4Result =
    "8f098d39ff65f95166cdb1c0aa5fcecd8677c3cb84fa8562c252b0789a6ec99175a8372d246dd1a474c0a5ac8f6d763a"
    "e0687864797f8d7053a291f969059791a276fd3580da2527b16c057efea3b4b61a5252af374d3b6ba893231c59ec6e22"
    "b7c2bea05b4b108bd361e811de65113921ca0936e1e312f36ab1cd6a2463f538385a6d6cf850f8b9c6c6301eefbda352"
    "628117a76cc40064928398ec2e259b22ed6a44ed890a8d09184d8944d847cefc471cf66a3995400705e724f16ea99208"
    "b0ef76ef16f774cafd206d61e48fe593a3f8f2d919d90da064ea8efef3f24628cea1821e233036c05f128d656fb47e4e"
    "8a4c5c5a3e7ae4fc53508e0842915ea7982de978e9d683b0155321665a0ae38bb45155fff6f2638c06f38771b30bfb8e"
    "eec5bc1d0a5bea0838c094c4c017f39fb8a41033f67f8597e017c0f075975d8443c204943fe22565b53cb4b59efa6155"
    "60fc0192b17d99ea05d895ae2589eade023f81703fb5e5bd718c5e2303c8c8ebd3d32d0caaf41b1a43a78ce6a9ca15ee";
// Reduction KAT: 512-byte value mod N and mod KAT1 modulus
const char* const kRedWide =
    "1609f620a7d63a5b05969f6a64155063cacea1d5f5777418a3a8205dd5f2c4d9346f4980314246b434f241cb65c8629f"
    "88feac8d0729f671f2c2138cd883907a206db7159f34e16995ab15babc898d57226f23b0d750fd50bb24845f4b211e14"
    "9bb32fe455ded333e48cb714ea643e497e0100a4b72c4bb86dc7238aa67918f6b8f18bc06546a7a4c77e3df2e949b0e1"
    "a4fa21e6c2e2b09c1e3f7e21a2b04c00f10c928c8a0076ca03d26e61f07036f93bd7b64e19cb2eb9a1606fece5e9764f"
    "6969ce1a28285c803ec35f4719b9401fbb6a371dc74ba757ac37fddff4e2962033a3f0ce18b370c34689c6e20329e1f4"
    "aca8a767153fb9c738483274af9ec9f497c393538d2661c4529dac847c12a2f46362c10fcddeddf26f334ab495f6a424"
    "aa52e1d2118bf644a0e5c40a12bdb7658f886ba19b6bffae89f190dd46e7cd142e101600bd79d52786342010fe292b77"
    "01945c1a97af979d9925ca1ed5d80ad8c9bd0997d806e04f6435d816144a9d7b039e3dd3c96f54e41666d33504fe984e"
    "f770531178c3976e3722274451a162067129937c31f3ef47bf07d1238ae84c9236944cabd4afc604b79ce7f7804dd6c9"
    "a46de773a31845f1b649bd695a9c5572c725184cefd6ed17ce30e6312e9dfb9005e9ef498594b08ae4646bd803cac7ea"
    "f9165d8ee823f41d6a9e7cb2aaab6cc01b1e545993e627daa1584b4ade9123a2";
const char* const kRedWideModN =
    "1e1294cc778172cf09323a766557db5b401ea1e7cd303838bff1ca44033dab820c52d36ae3577373f81171962691c377"
    "aed5635c49cd1203334e6ae719972ba9c5c03ceac8cb0999a2676d7bc2144dd5400c25a59102e9b9f2d5457fde73adb0"
    "ed069afa6532831818df8a6f669f66ad5addc746f63542f31d2581137b0ae3ea593b74daeb18968a9cec146acbcba378"
    "64ce5cbbaf2f8d087dc9063e41c81ac5c4b585f69ed6024c2d870e7bb249781334f2efc076cd0df4c7c6597fa33d5c13"
    "aeba82572dacad60eef7875bb45066360c30dbd876cd63478a8334fcd7e3bd8b4dc12a970420e21d589de60fe2b17241"
    "e391745ece3ddb91cc280ec9ae9d115e82666b1d074e14bf42058578db28135e1192244cadb54302f4627784886c0ae4"
    "605ba5df081983bcc48d72e4aeab63aa9c4226137e4e0714d736c2619ba9db374b61b72c4f05e8b4c23567b109ccdeee"
    "a432ecc1eec4a0d22d4346be67948d99c32b4a585ae46add33a7310ceed2918cd68e0da9a890b5b1f3ae8a23299c57f6";
const char* const kRedWideModM2 =
    "18867e5e33973abcbb3eaab7f6c860ebfa63edda7d3e1957e6959ec959b90993a548adc341824c3d366c76351df268b1"
    "6f8c03af68c187aeba548f81cb127b83361b3f22422a904e077a9c7d050aa2c6303f9ab2a4dc97f117e1cb1a203cb62c"
    "76f0144b8aabca71243c25e30e4e8a130795d3efa429ebe5ba728451dfa2219fe9dca3c8bf3bb910154fec81ffe6d489"
    "b4ae04f1669f440bccb942342f4fe643900ee3bb4e7943564914874857926b0a637c6f23f007ae3477c626af55f8ede3"
    "6c829497978a2a62a7b66a641d81bfa26c4631a19154cd9ad7bb12177b693de10e25ab385ce914298c90017bd604d695"
    "b681de52fc292a942f8f27cf404968b9";
// mulMod KAT on N
const char* const kMulA =
    "547b7292259513e922dbec2c8f029f5a3e25442de7c437b7f65cdadd92daf14bf779bfafb4f23d8a33cea48e2d347fe4"
    "d5130a83fd85f97b07e60bdc2e042ca308648fdad5cf01225c84bf470cfcdd3965f94ff647ee293983321ce382623f26"
    "27dff9707868654e0a183d00ac280a2186f16aaa8d820581f0393746f99da7d47e375ba8c5025c27e9dc52fcffbb383f"
    "3e05bd8382a0cfeeb6073b594c125cda9a40dd66deaef86cbbb3f8af8356474f584db459116f9e731ed35953465b91bf"
    "b33c7a702ddb65c44b4828437f3cd5f3eca8415aa55983ed39d33e754ed028ecde3268898779b875efb9321d93e31cff"
    "8a7973a9a5f36f7c1f09742f1fc312d44b98c329c4330ed9db5f3179e8f63fab0fbd3986fab7d550b03f588dc29ee354"
    "d8b0b9a7b8f949ed8ce7bf6d62bdf73857bc852a8d4bdbb913cc71144b6ba6125ecf5f7b3b25263cf05e43b2b56c65e3"
    "901d7206008a9b6c540523843a0b2db1bd82f7fc6d2555462af567dcf5aa4c551af6710e76449762b466469663d6b1";
const char* const kMulB =
    "07ed13b939911ad8fec091fcfb1de5f8011f34176827b1104e8971505d9abbc33f3751186bec104c7fcc2d3f14bf6d5a"
    "52e03861a814851028925b8978eeef8423bbe8fcc3955099c4b40856577466bf00feaf38bfd332d03190b289c8db6b5c"
    "8147a1e920b78aa7282b44cf3bf85ea589fb01439426a9af5c00e5a800aae01058f1b08601e2fb030b945e98da057dc8"
    "15a091ce659bd0069ea28b85d002b2ab58f6c8f0dd2b0a1b60fcd3ce0d904109fe9ba7116e2405cb733a4841d82593d1"
    "7f040ea83e462becbe91430324e7cfbd3ba13803fee0b17badfab973407c5f0993d999a76a47d06902cd5e2530015452"
    "e41a0d48aa3755e0ef298680371938a50e6a39012078a5217737e4ee264ad3365f0f2fa125c1195c0566156f8428c2cb"
    "579e297e06488b78d6f8f0f05498ae7925b9b959f70dc5a52a550deaafd860e49cf2a298c3acf4653cabfb987427d05d"
    "78fc492681ec49dda07f54f0d4dba032c31af3ad281e906d608613c047a64e7fdbff1948934d28bd88a6918c35ad9a";
const char* const kMulResult =
    "bd9d4c08dedb988faea31a51d4a6e832b8150b386f9e540cce6a13741f4f90d0a53afd522671bc065f0508b65b1e35c5"
    "d91541686a520be0e71584b18744566b616b243759600124034540ebe2d5a69663125e4e7fcea67faa364f4a1e0284fa"
    "0e8733f9bf46a3104985e749c913a09bda04fe3e7564680b4c1463073f8fb1a7da90526517bb53dab2468ba8f3b5882e"
    "8729ad24ada28e66a47bb52e2bd1015f409d1c4512ca08f1171279392eca8746ca97df70fa5ceb476053cd755e2a9ae0"
    "175d7d7fc768fb7887a61f0bd833bb7b08c22a79c1d54ef74f91531dfd00d22dbcf0619e27ed98f31189b105db36400c"
    "e8f238c2950dcccd915265a649146ce1ce0fa9261e4e94c2baaa4204ff90c75b68c2792e661b6d6be873ff1d4cd92356"
    "29e3c830847e9a0fd4e5b7f4a4289b007f3c7895fecb2c482a595466d71608432960b148c91a1071aa5396043778c00c"
    "7610e685ade46f8833e3d43c2ad70c8f2bc5ca79202f34d1ff5419c2027bb08e6ce964be9081a9791079570b7ef1eb84";

Number num(const std::string& hex) {
    const std::vector<uint8_t> b = hexToBytes(hex);
    Number n;
    bi::fromBytesBE(b.empty() ? NULL : &b[0], b.size(), n);
    return n;
}

Number num64(uint64_t v) {
    Number n;
    n.limbs[0] = static_cast<uint32_t>(v);
    n.limbs[1] = static_cast<uint32_t>(v >> 32);
    return n;
}

std::string hexOf(const Number& n) {
    std::vector<uint8_t> b;
    bi::toBytesBE(n, b);
    return bytesToHex(b);
}

std::string normHex(const std::string& hex) {
    std::vector<uint8_t> b = hexToBytes(hex);
    size_t i = 0;
    while (i + 1 < b.size() && b[i] == 0) ++i;
    return bytesToHex(std::vector<uint8_t>(b.begin() + static_cast<long>(i), b.end()));
}

std::vector<uint8_t> beU64(uint64_t v) {
    std::vector<uint8_t> out;
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<uint8_t>(v >> (i * 8)));
    return out;
}

bool modExpBytes(const Modulus& m, const Number& base, const std::vector<uint8_t>& e, Number& out) {
    return m.modExp(base, e.empty() ? NULL : &e[0], e.size(), out);
}

// Big-endian byte-string addition (independent of the bigint module).
std::vector<uint8_t> addBE(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = (a.size() > b.size() ? a.size() : b.size()) + 1;
    std::vector<uint8_t> out(n, 0);
    unsigned carry = 0;
    for (size_t i = 0; i < n; ++i) {
        unsigned s = carry;
        if (i < a.size()) s += a[a.size() - 1 - i];
        if (i < b.size()) s += b[b.size() - 1 - i];
        out[n - 1 - i] = static_cast<uint8_t>(s);
        carry = s >> 8;
    }
    return out;
}

// Reference modexp for moduli < 2^32 using plain uint64_t arithmetic.
uint32_t refModExp32(uint32_t base, uint64_t exp, uint32_t mod) {
    uint64_t result = 1 % mod;
    uint64_t b = base % mod;
    while (exp != 0) {
        if (exp & 1U) result = (result * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return static_cast<uint32_t>(result);
}

Modulus primeN() {
    Modulus m;
    Number n;
    bi::fromBytesBE(carplay::srp::rfc5054Prime3072(), carplay::srp::kPrimeBytes, n);
    m.init(n);
    return m;
}

std::vector<uint8_t> nMinusOneBytes() {
    std::vector<uint8_t> e(carplay::srp::rfc5054Prime3072(),
                           carplay::srp::rfc5054Prime3072() + carplay::srp::kPrimeBytes);
    e[e.size() - 1] = static_cast<uint8_t>(e[e.size() - 1] - 1);  // N ends in 0xff
    return e;
}

}  // namespace

TEST_CASE(byteConversionRoundTrips) {
    // Leading zeros are stripped by the minimal encoding.
    const std::vector<uint8_t> in = hexToBytes("0000 0102030405060708090a");
    Number n;
    REQUIRE(bi::fromBytesBE(&in[0], in.size(), n));
    CHECK_EQ(std::string("0102030405060708090a"), hexOf(n));
    CHECK_EQ(0x0708090aU, n.limbs[0]);
    CHECK_EQ(0x03040506U, n.limbs[1]);
    CHECK_EQ(0x00000102U, n.limbs[2]);
    CHECK_EQ(static_cast<size_t>(73), bi::bitLength(n));

    std::vector<uint8_t> padded;
    REQUIRE(bi::toBytesBEPadded(n, 16, padded));
    CHECK_BYTES_EQ(hexToBytes("000000000000 0102030405060708090a"), padded);
    REQUIRE(bi::toBytesBEPadded(n, 10, padded));
    CHECK_BYTES_EQ(hexToBytes("0102030405060708090a"), padded);
    CHECK(!bi::toBytesBEPadded(n, 9, padded));
    CHECK(padded.empty());

    // Zero.
    Number z;
    CHECK(bi::isZero(z));
    CHECK_EQ(std::string("00"), hexOf(z));
    REQUIRE(bi::toBytesBEPadded(z, 4, padded));
    CHECK_BYTES_EQ(hexToBytes("00000000"), padded);
    REQUIRE(bi::fromBytesBE(NULL, 0, z));
    CHECK(bi::isZero(z));
    CHECK_EQ(static_cast<size_t>(0), bi::bitLength(z));

    // Full-width 384-byte values; 385 bytes allowed only with a leading zero.
    std::vector<uint8_t> big(384, 0xa5);
    big[0] = 0x80;
    REQUIRE(bi::fromBytesBE(&big[0], big.size(), n));
    CHECK_EQ(static_cast<size_t>(3072), bi::bitLength(n));
    std::vector<uint8_t> back;
    bi::toBytesBE(n, back);
    CHECK_BYTES_EQ(big, back);
    std::vector<uint8_t> big385(1, 0);
    big385.insert(big385.end(), big.begin(), big.end());
    Number n2;
    REQUIRE(bi::fromBytesBE(&big385[0], big385.size(), n2));
    CHECK_EQ(0, bi::compare(n, n2));
    big385[0] = 1;
    CHECK(!bi::fromBytesBE(&big385[0], big385.size(), n2));
    CHECK(bi::isZero(n2));

    // Minimal encoding of a value whose top limb is partially filled.
    const Number odd = num("00ab");
    CHECK_EQ(std::string("ab"), hexOf(odd));
    CHECK_EQ(-1, bi::compare(odd, n));
    CHECK_EQ(1, bi::compare(n, odd));
}

TEST_CASE(modulusInitRejectsEvenAndTiny) {
    Modulus m;
    CHECK(!m.init(bi::fromUint32(0)));
    CHECK(!m.valid());
    CHECK(!m.init(bi::fromUint32(1)));
    CHECK(!m.init(bi::fromUint32(1000)));
    CHECK(!m.init(num("0100000000000000000000")));  // even multi-limb
    Number r;
    const uint8_t e = 10;
    CHECK(!m.modExp(bi::fromUint32(2), &e, 1, r));
    CHECK(m.init(bi::fromUint32(3)));
    CHECK(m.valid());
    CHECK_EQ(static_cast<size_t>(1), m.limbCount());
    CHECK(m.init(num("010000000000000001")));
    CHECK_EQ(static_cast<size_t>(3), m.limbCount());
}

TEST_CASE(smallKnownAnswerModExp) {
    Modulus m;
    Number r;
    REQUIRE(m.init(bi::fromUint32(497)));
    const uint8_t e13 = 13;
    REQUIRE(m.modExp(bi::fromUint32(4), &e13, 1, r));
    CHECK_EQ(0, bi::compare(bi::fromUint32(445), r));

    REQUIRE(m.init(bi::fromUint32(1001)));
    const uint8_t e10 = 10;
    REQUIRE(m.modExp(bi::fromUint32(2), &e10, 1, r));
    CHECK_EQ(0, bi::compare(bi::fromUint32(23), r));  // 1024 mod 1001

    // Odd moduli < 2^32 against a plain uint64_t reference.
    const uint32_t mods[] = {3U, 5U, 497U, 65537U, 2147483647U, 4294967291U, 4294967295U, 123456789U};
    const uint32_t bases[] = {0U, 1U, 2U, 7U, 65535U, 4294967295U};
    const uint64_t exps[] = {0ULL, 1ULL, 2ULL, 65537ULL, 0xdeadbeefULL, 0xffffffffffffffffULL};
    for (size_t mi = 0; mi < sizeof(mods) / sizeof(mods[0]); ++mi) {
        REQUIRE(m.init(bi::fromUint32(mods[mi])));
        for (size_t bi_ = 0; bi_ < sizeof(bases) / sizeof(bases[0]); ++bi_) {
            for (size_t ei = 0; ei < sizeof(exps) / sizeof(exps[0]); ++ei) {
                REQUIRE(modExpBytes(m, bi::fromUint32(bases[bi_]), beU64(exps[ei]), r));
                CHECK_EQ(refModExp32(bases[bi_], exps[ei], mods[mi]), r.limbs[0]);
                CHECK_EQ(0U, r.limbs[1]);
            }
        }
    }
}

TEST_CASE(fermatOnMultiLimbMersennePrimes) {
    // 2^61-1 (2 limbs), 2^89-1 (3 limbs), 2^127-1 (4 limbs) are Mersenne primes.
    const char* const primes[] = {
        "1fffffffffffffff",
        "01ffffffffffffffffffffff",
        "7fffffffffffffffffffffffffffffff",
    };
    for (size_t i = 0; i < 3; ++i) {
        Modulus m;
        REQUIRE(m.init(num(primes[i])));
        std::vector<uint8_t> pm1 = hexToBytes(primes[i]);
        pm1[pm1.size() - 1] = static_cast<uint8_t>(pm1[pm1.size() - 1] - 1);
        const std::vector<uint8_t> p = hexToBytes(primes[i]);
        const char* const bases[] = {"02", "05", "0123456789abcdef", "1ffffffffffffffe"};
        for (size_t b = 0; b < 4; ++b) {
            Number r;
            REQUIRE(modExpBytes(m, num(bases[b]), pm1, r));
            CHECK_EQ(std::string("01"), hexOf(r));
            // a^p == a (mod p)
            Number a;
            REQUIRE(m.reduce(num(bases[b]), a));
            REQUIRE(modExpBytes(m, num(bases[b]), p, r));
            CHECK_EQ(0, bi::compare(a, r));
        }
    }
}

TEST_CASE(edgeExponentsAndBases) {
    const Modulus m = primeN();
    REQUIRE(m.valid());
    CHECK_EQ(static_cast<size_t>(96), m.limbCount());
    const Number a = num(kMulA);
    Number r;

    REQUIRE(m.modExp(a, NULL, 0, r));  // empty exponent
    CHECK_EQ(std::string("01"), hexOf(r));
    const std::vector<uint8_t> zeros(40, 0);
    REQUIRE(modExpBytes(m, a, zeros, r));  // all-zero exponent
    CHECK_EQ(std::string("01"), hexOf(r));
    REQUIRE(modExpBytes(m, a, hexToBytes("000001"), r));  // a^1 with leading zero bytes
    CHECK_EQ(0, bi::compare(a, r));
    REQUIRE(modExpBytes(m, Number(), hexToBytes("05"), r));  // 0^e
    CHECK(bi::isZero(r));
    REQUIRE(modExpBytes(m, Number(), zeros, r));  // 0^0 == 1 (BigInteger convention)
    CHECK_EQ(std::string("01"), hexOf(r));

    // base == N -> 0.
    REQUIRE(modExpBytes(m, m.value(), hexToBytes("03"), r));
    CHECK(bi::isZero(r));
    // N - 1 is the largest reduced value; (N-1)^2 == 1.
    std::vector<uint8_t> nm1 = nMinusOneBytes();
    Number nm1n = num(bytesToHex(nm1));
    REQUIRE(modExpBytes(m, nm1n, hexToBytes("02"), r));
    CHECK_EQ(std::string("01"), hexOf(r));

    // Aliasing: out == base.
    Number al = bi::fromUint32(7);
    REQUIRE(modExpBytes(m, al, hexToBytes("02"), al));
    CHECK_EQ(std::string("31"), hexOf(al));

    // Small modulus: base wider than modulus is reduced first.
    Modulus s;
    REQUIRE(s.init(bi::fromUint32(497)));
    REQUIRE(modExpBytes(s, num("0100000000000000000004"), hexToBytes("0d"), r));
    // 2^80 + 4 mod 497 computed below via the module's own reduce, cross-checked with refModExp32.
    Number red;
    REQUIRE(s.reduce(num("0100000000000000000004"), red));
    CHECK_EQ(refModExp32(red.limbs[0], 13, 497), r.limbs[0]);
    // 2^80 mod 497 by repeated doubling with uint64_t.
    uint64_t p = 1;
    for (int i = 0; i < 80; ++i) p = (p * 2) % 497;
    CHECK_EQ(static_cast<uint32_t>((p + 4) % 497), red.limbs[0]);
}

TEST_CASE(addSubMulModSmall) {
    Modulus m;
    REQUIRE(m.init(bi::fromUint32(497)));
    for (uint32_t a = 0; a < 497; a += 37) {
        for (uint32_t b = 0; b < 60; b += 7) {
            Number acc;
            for (uint32_t i = 0; i < b; ++i) {
                REQUIRE(m.addMod(acc, bi::fromUint32(a), acc));
            }
            Number prod;
            REQUIRE(m.mulMod(bi::fromUint32(a), bi::fromUint32(b), prod));
            CHECK_EQ(0, bi::compare(acc, prod));
            CHECK_EQ((a * b) % 497U, prod.limbs[0]);
            Number d;
            REQUIRE(m.subMod(bi::fromUint32(a), bi::fromUint32(b), d));
            CHECK_EQ((a + 497U - b) % 497U, d.limbs[0]);
        }
    }
    Number out;
    CHECK(!m.addMod(bi::fromUint32(497), bi::fromUint32(1), out));
    CHECK(!m.mulMod(bi::fromUint32(1), bi::fromUint32(500), out));
    CHECK(!m.subMod(bi::fromUint32(498), bi::fromUint32(1), out));

    // Two-limb modulus crossing the 32-bit boundary.
    const uint64_t p = 0x1fffffffffffffffULL;  // 2^61 - 1
    REQUIRE(m.init(num64(p)));
    const uint64_t x = 0x1234567890abcdefULL % p;
    const uint64_t y = 0x0fedcba987654321ULL % p;
    Number s;
    REQUIRE(m.addMod(num64(x), num64(y), s));
    CHECK_EQ(0, bi::compare(num64((x + y) % p), s));
    REQUIRE(m.subMod(num64(y), num64(x), s));
    CHECK_EQ(0, bi::compare(num64((y + p - x) % p), s));
    // mulMod vs 2^61-1 folding: x*y mod p via schoolbook halves in uint64_t.
    uint64_t acc = 0;
    uint64_t addend = x;
    uint64_t yy = y;
    while (yy != 0) {
        if (yy & 1U) acc = (acc + addend) % p;
        addend = (addend * 2) % p;
        yy >>= 1;
    }
    REQUIRE(m.mulMod(num64(x), num64(y), s));
    CHECK_EQ(0, bi::compare(num64(acc), s));
}

TEST_CASE(largeSubModAndAddModWrap) {
    const Modulus m = primeN();
    const Number a = num(kMulA);
    const Number b = num(kMulB);
    Number d;
    Number back;
    REQUIRE(m.subMod(a, b, d));
    REQUIRE(m.addMod(d, b, back));
    CHECK_EQ(0, bi::compare(a, back));
    REQUIRE(m.subMod(Number(), bi::fromUint32(1), d));
    CHECK_EQ(bytesToHex(nMinusOneBytes()), hexOf(d));
    REQUIRE(m.addMod(d, bi::fromUint32(1), back));
    CHECK(bi::isZero(back));
}

TEST_CASE(reductionOfWideValues) {
    const Modulus m = primeN();
    const std::vector<uint8_t> wide = hexToBytes(kRedWide);
    REQUIRE(wide.size() == 512);
    Number r;
    REQUIRE(m.reduce(&wide[0], wide.size(), r));
    CHECK_EQ(normHex(kRedWideModN), hexOf(r));

    Modulus m2;
    REQUIRE(m2.init(num(kKat1Mod)));
    REQUIRE(m2.reduce(&wide[0], wide.size(), r));
    CHECK_EQ(normHex(kRedWideModM2), hexOf(r));

    // 513 bytes are rejected even with a leading zero.
    std::vector<uint8_t> w513(1, 0);
    w513.insert(w513.end(), wide.begin(), wide.end());
    CHECK(!m.reduce(&w513[0], w513.size(), r));

    // N, 2N, 3N reduce to zero; 2N + 7 reduces to 7.
    const std::vector<uint8_t> nb(carplay::srp::rfc5054Prime3072(),
                                  carplay::srp::rfc5054Prime3072() + 384);
    REQUIRE(m.reduce(&nb[0], nb.size(), r));
    CHECK(bi::isZero(r));
    const std::vector<uint8_t> n2 = addBE(nb, nb);
    REQUIRE(m.reduce(&n2[0], n2.size(), r));
    CHECK(bi::isZero(r));
    const std::vector<uint8_t> n3 = addBE(n2, nb);
    REQUIRE(m.reduce(&n3[0], n3.size(), r));
    CHECK(bi::isZero(r));
    const std::vector<uint8_t> n2p7 = addBE(n2, hexToBytes("07"));
    REQUIRE(m.reduce(&n2p7[0], n2p7.size(), r));
    CHECK_EQ(std::string("07"), hexOf(r));
    REQUIRE(m.reduce(NULL, 0, r));
    CHECK(bi::isZero(r));
}

TEST_CASE(knownAnswerModExpFromDotNet) {
    const char* const mods[] = {kKat0Mod, kKat1Mod, kKat2Mod, kKat3Mod, kKat4Mod};
    const char* const bases[] = {kKat0Base, kKat1Base, kKat2Base, kKat3Base, kKat4Base};
    const char* const exps[] = {kKat0Exp, kKat1Exp, kKat2Exp, kKat3Exp, kKat4Exp};
    const char* const results[] = {kKat0Result, kKat1Result, kKat2Result, kKat3Result, kKat4Result};
    for (size_t i = 0; i < 5; ++i) {
        Modulus m;
        REQUIRE(m.init(num(mods[i])));
        Number r;
        REQUIRE(modExpBytes(m, num(bases[i]), hexToBytes(exps[i]), r));
        CHECK_EQ(normHex(results[i]), hexOf(r));
    }
    // mulMod KAT.
    const Modulus n = primeN();
    Number r;
    REQUIRE(n.mulMod(num(kMulA), num(kMulB), r));
    CHECK_EQ(normHex(kMulResult), hexOf(r));
}

TEST_CASE(exponentLawsOnPrime3072) {
    const Modulus m = primeN();
    const Number a = num(kMulA);
    const Number b = num(kMulB);
    const std::vector<uint8_t> e1 = hexToBytes(kKat0Exp);  // 64 bytes
    const std::vector<uint8_t> e2 = hexToBytes(kKat3Exp);  // 32 bytes
    const std::vector<uint8_t> e12 = addBE(e1, e2);

    Number x1, x2, x12, prod;
    REQUIRE(modExpBytes(m, a, e1, x1));
    REQUIRE(modExpBytes(m, a, e2, x2));
    REQUIRE(modExpBytes(m, a, e12, x12));
    REQUIRE(m.mulMod(x1, x2, prod));
    CHECK_EQ(0, bi::compare(x12, prod));

    Number ab, abe, ae, be, aebe;
    REQUIRE(m.mulMod(a, b, ab));
    REQUIRE(modExpBytes(m, ab, e1, abe));
    REQUIRE(modExpBytes(m, a, e1, ae));
    REQUIRE(modExpBytes(m, b, e1, be));
    REQUIRE(m.mulMod(ae, be, aebe));
    CHECK_EQ(0, bi::compare(abe, aebe));

    // (a^e1)^e2 == (a^e2)^e1
    Number y1, y2;
    REQUIRE(modExpBytes(m, x1, e2, y1));
    REQUIRE(modExpBytes(m, x2, e1, y2));
    CHECK_EQ(0, bi::compare(y1, y2));
}

TEST_CASE(fermatOnPrime3072) {
    const Modulus m = primeN();
    const std::vector<uint8_t> nm1 = nMinusOneBytes();
    const char* const bases[] = {"02", "05", kKat0Base /* 384 bytes, may exceed N */, kKat4Base};
    for (size_t i = 0; i < 4; ++i) {
        Number r;
        REQUIRE(modExpBytes(m, num(bases[i]), nm1, r));
        CHECK_EQ(std::string("01"), hexOf(r));
    }
    // Safe prime: 2 is a quadratic residue mod N here iff 2^((N-1)/2) == 1; for this group
    // (N = 7 mod 8) 2 is a QR, so 2^((N-1)/2) == 1 and 5^((N-1)/2) == N-1 (5 generates).
    std::vector<uint8_t> half(nm1.size(), 0);
    unsigned carry = 0;
    for (size_t i = 0; i < nm1.size(); ++i) {
        const unsigned cur = (carry << 8) | nm1[i];
        half[i] = static_cast<uint8_t>(cur >> 1);
        carry = cur & 1U;
    }
    Number r;
    REQUIRE(modExpBytes(m, bi::fromUint32(2), half, r));
    CHECK_EQ(std::string("01"), hexOf(r));
    REQUIRE(modExpBytes(m, bi::fromUint32(5), half, r));
    CHECK_EQ(bytesToHex(nm1), hexOf(r));
}

int main() {
    return test_support::runAll("test_bigint");
}
