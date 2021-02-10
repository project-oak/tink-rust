// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

// # Test vectors generated from libsodium with this code:
//
// #include <stdio.h>
// #include <sodium.h>
// #include <stdlib.h>
//
// void hexdump(const uint8_t *in, size_t in_len) {
//   for (size_t i = 0; i < in_len; i++) {
//     printf("%02x", in[i]);
//   }
//   printf("\n");
// }
//
// int main() {
//   uint8_t nonce[24];
//   uint8_t key[32];
//   uint8_t m[64], c[64];
//   uint8_t ad[16], tag[16];
//
//   for (size_t ad_len = 0; ad_len < sizeof(ad); ad_len += 4) {
//     for (size_t m_len = 0; m_len < sizeof(m); m_len += 5) {
//       randombytes(nonce, sizeof(nonce));
//       randombytes(key, sizeof(key));
//       randombytes(m, m_len);
//       randombytes(ad, ad_len);
//
//       unsigned long long tag_len = sizeof(tag);
//
//       if (crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
//               c, tag, &tag_len, m, m_len, ad, ad_len, NULL, nonce, key)) {
//         abort();
//       }
//
//       printf("KEY: ");
//       hexdump(key, sizeof(key));
//       printf("NONCE: ");
//       hexdump(nonce, sizeof(nonce));
//       printf("IN: ");
//       hexdump(m, m_len);
//       printf("AD: ");
//       hexdump(ad, ad_len);
//       printf("CT: ");
//       hexdump(c, m_len);
//       printf("TAG: ");
//       hexdump(tag, sizeof(tag));
//       printf("\n");
//     }
//   }
//
//   return 0;
// }

pub struct XChaCha20Poly1305Test {
    pub key: &'static str,
    pub nonce: &'static str,
    pub plaintext: &'static str,
    pub aad: &'static str,
    pub out: &'static str,
    pub tag: &'static str,
}

pub const X_CHA_CHA20_POLY1305_TESTS: &[XChaCha20Poly1305Test] = &[
    XChaCha20Poly1305Test {
        key:       "1f4774fbe6324700d62dd6a104e7b3ca7160cfd958413f2afdb96695475f007e",
        nonce:     "029174e5102710975a8a4a936075eb3e0f470d436884d250",
        plaintext: "",
        aad:       "",
        out:       "",
        tag:       "f55cf0949af356f977479f1f187d7291",
    },
    XChaCha20Poly1305Test {
        key:       "eb27969c7abf9aff79348e1e77f1fcba7508ceb29a7471961b017aef9ceaf1c2",
        nonce:     "990009311eab3459c1bee84b5b860bb5bdf93c7bec8767e2",
        plaintext: "e7ec3d4b9f",
        aad:       "",
        out:       "66bd484861",
        tag:       "07e31b4dd0f51f0819a0641c86380f32",
    },
    XChaCha20Poly1305Test {
        key:       "4b6d89dbd7d019c0e1683d4c2a497305c778e2089ddb0f383f2c7fa2a5a52153",
        nonce:     "97525eb02a8d347fcf38c81b1be5c3ba59406241cf251ba6",
        plaintext: "074db54ef9fbc680b41a",
        aad:       "",
        out:       "1221898afd6f516f770f",
        tag:       "75e7182e7d715f5a32ee6733fd324539",
    },
    XChaCha20Poly1305Test {
        key:       "766997b1dc6c3c73b1f50e8c28c0fcb90f206258e685aff320f2d4884506c8f4",
        nonce:     "30e7a9454892ef304776b6dc3d2c2f767ed97041b331c173",
        plaintext: "b8250c93ac6cf28902137b4522cc67",
        aad:       "",
        out:       "e2a13eeff8831a35d9336cb3b5c5d9",
        tag:       "62fdf67735cad0172f9b88603b5f3c13",
    },
    XChaCha20Poly1305Test {
        key:       "6585031b5649fcabd9d4971d4ac5646fc7dca22f991dfa7dac39647001004e20",
        nonce:     "705ee25d03fec430e24c9c6ccaa633f5b86dd43682778278",
        plaintext: "9a4ca0633886a742e0241f132e8f90794c34dfd4",
        aad:       "",
        out:       "0a8e6fd4cd1640be77c4c87dde4ae6222c887ed7",
        tag:       "edc4fbc91dfa07021e74ae0d9d1c98dc",
    },
    XChaCha20Poly1305Test {
        key:       "dfc6f7c86a10a319ebcb6362997e585f55b67f3434f47dc4039c2d67973e3077",
        nonce:     "6097f30fd75229d928454c7d59a2d2c58bfddcb14c16438e",
        plaintext: "74c946a7f0733377e852a23087506a28dccef86e101a4359c0",
        aad:       "",
        out:       "6e8ea0bb4c2f1323841d8e236816c61c3295866b75cefb5c25",
        tag:       "f16c0e9487ca7de5e7cb2a1b8bb370fc",
    },
    XChaCha20Poly1305Test {
        key:       "59b8d488773767c4804d918709cfec6c69a193371145bb94f183899851aaadac",
        nonce:     "ad5bdf8f190ca2d2cc02a75bb62aa22274cb3c98fe2d25f2",
        plaintext: "066b9ed10f16d3dc132b409aae02d8cac209dd9b4fb789c4d34725ab2a1f",
        aad:       "",
        out:       "2bbd4542489006df66ad1462a932524642b139ddcbf86b6b480e9e6d976c",
        tag:       "ca4835419ba029bc57010a8cc8bca80c",
    },
    XChaCha20Poly1305Test {
        key:       "8c0cb4633cf8dc6b4b9552d1035f85517cb1ba4c36bcbc43338a8c6c7d15ce20",
        nonce:     "8418b9655a0376fadefa3cdf8805815c4f7b56f467a74a95",
        plaintext: "50c205a9c5d4088ba8e59a96fcd837f5170669854547678288199f1078ff2a81f0b19a",
        aad:       "",
        out:       "8b55a12df1a85dd3fb19c34ab047a85849d15a30225bb5360bad1f0a8f5f2bd49f5898",
        tag:       "bce13201df6e4a7e6d896262e45d969d",
    },
    XChaCha20Poly1305Test {
        key:       "b45386a75a5772e34bd193e1946f69ebfb90c37ae4581d39c9669d75e4584f50",
        nonce:     "9fb763d0926585b5f726af9b8e3babdb331e9aa97f8d99ed",
        plaintext: "64df0e341145d9e4a0d090153591a74893bc36cb9dae1e9570d8fee62e907cf004f9d8a360343483",
        aad:       "",
        out:       "3146d8a5c898edd832ec9d126e93b3a433ec97dc47dce0e1985bda88c88c6aeca46fc7d9a68e30ab",
        tag:       "44fdb0d69abd8068442cb2ea6df8b2f2",
    },
    XChaCha20Poly1305Test {
        key:       "f2efbd358dd353639a162be39a957d27c0175d5ab72aeba4a266aeda434e4a58",
        nonce:     "65a6f7ebe48de78beb183b518589a0afacf71b40a949fa59",
        plaintext: "f7473947996e6682a3b9c720f03cfaf26bbcdaf76c83342d2ad922435e227a5d1eacbd9bd6ea1727ec19fb0e42",
        aad:       "",
        out:       "778a0fb701b9d671ccfaf1454e8928158ede9bb4395119356a8133036840c1bcbb8fe5e19922fbbcf8b18596e7",
        tag:       "9d195a89fdd29ca271405d3330f996f9",
    },
    XChaCha20Poly1305Test {
        key:       "9dd674fb4a30a7bb85fc78050479ab0e2c3cc9f9f5b8689a7a67413aca304b21",
        nonce:     "ad9e8fe15940694725f232e88f79cda7c82fe1b8aae58ba4",
        plaintext: "7272bb6609cbd1399a0b89f6ea255165f99330aeb170ac88fccdd8e226df0952407e35718fb5edc9e987faabb271cc69f7e7",
        aad:       "",
        out:       "846901650cb38974463a18c367676e1579ebdaf3e96b57224e842f5d5f678f3270b9a15f01241795662befb3db0768800e25",
        tag:       "900004db3613acbeb33d65d74dd437d7",
    },
    XChaCha20Poly1305Test {
        key:       "280cbe7380a0d8bb4d8dd4476012f2eeb388a37b8b71067969abb99f6a888007",
        nonce:     "2e1854617c67002599e6b077a812c326deb22fe29d093cbb",
        plaintext: "d0901ec3d31ece2832685ff577f383bdff26c31341ea254acee7c5929a5df74fea2aa964524dc680b2f55fbd4fea900e956c304cc4ac3c",
        aad:       "",
        out:       "546370726cc63068d3520d67f4f57f65d03b9ecec21c2a8c7b1133089ad28b07025a7181bddeb4a49f514fac1a44f64ee3af33d778fb98",
        tag:       "39084e33e42a1b05f58da65ba487d138",
    },
    XChaCha20Poly1305Test {
        key:       "887564f75afa78f595cdadcea7340d20f5c5a2df169d0ad14b15fe32ce337004",
        nonce:     "54c11df13d1f444da80b0964caeb59474b17b23a650a33f5",
        plaintext: "f0f008eece79ecb24b715dff8a3456dfe253924b99f98f2f1b18564cced50925fca860d1c2d4785bdf4a964c76c3079efa6b37c4ba2cacc534fb590c",
        aad:       "",
        out:       "32bb077268568d569b39e8ccdeeeb447ef424eaa2ffab565209a19b16a25952f897e5405bb0d67d8c9005d1c0b32687164d17fa4d0f412b80414c025",
        tag:       "0bac7c0f8dce12917fbd4ed1738ac0cc",
    },
    XChaCha20Poly1305Test {
        key:       "21c6aa88eb1a320d251f71a4b312ca75347040990d869a1dd2a1982c30fda2c7",
        nonce:     "7dead2f1a3d9d45a9124a40efe8994300976991a4417ef4d",
        plaintext: "",
        aad:       "e1bf7de4",
        out:       "",
        tag:       "341e9d0687006f981bced2f985f953e6",
    },
    XChaCha20Poly1305Test {
        key:       "0c97b9a65ffcd80b8f7c20c3904d0d6dd8809a7f97d7f46d39a12c198a85da5d",
        nonce:     "1f2c1dbc5f52fc9c8f9ca7695515d01d15904b86f703fba3",
        plaintext: "ecaf65b66d",
        aad:       "bd8a6f18",
        out:       "8d1b2b0e38",
        tag:       "27a7c7ac8bda627085414f0f31206a07",
    },
    XChaCha20Poly1305Test {
        key:       "4ab5e3595f39c4379a924e5f8ebcf3279075c08d18daff01d9ddfa40e03faf12",
        nonce:     "94e6ddc294f5f1531924ec018823343ebcc220a88ea5ee33",
        plaintext: "c91b73abe5316c3effc6",
        aad:       "c576f6ea",
        out:       "abe960fbc64b339c53b1",
        tag:       "7ebae48a2ff10117069324f04619ad6f",
    },
    XChaCha20Poly1305Test {
        key:       "a1e6146c71c2ea22300e9063455f621e15bd5bf1a3762e17f845e1aba5dd5a9c",
        nonce:     "82ddb6929abff8a9ad03dfb86c0bb3e7c092d45ebfa60a1b",
        plaintext: "f011f32ccc2955158c117f53cf7b12",
        aad:       "5d14bc05",
        out:       "44592321c665f51e9ffea052df1fea",
        tag:       "d556798b97f9b647729801419424affc",
    },
    XChaCha20Poly1305Test {
        key:       "7a1af30362c27fd55b8c24b7fca324d350decee1d1f8fae56b66253a9dd127dd",
        nonce:     "61201d6247992002e24e1a893180d4f0c19a3ae4cc74bf0c",
        plaintext: "5c7150b6a4daa362e62f82f676fdc4c4b558df64",
        aad:       "00c49210",
        out:       "27d9e2730b6809c08efbd4b0d24639c7b67486f3",
        tag:       "5889fdee25379960038778e36b2cedb2",
    },
    XChaCha20Poly1305Test {
        key:       "0b3fd9073e545ac44a7967263ead139c9547f7a54f06228fd3c8609fa2620784",
        nonce:     "6450e1097d6f9ea76eb42e8e65972d501041c3a58baf8770",
        plaintext: "d679ae442b0351e5bff9906b099d45aab4f6aea5306a7a794f",
        aad:       "318d292b",
        out:       "a3f9ee45316d7b0f948a26145ee4fd0552bc6dc25e577e777a",
        tag:       "0068a401a194b8417ec0e198baa81830",
    },
    XChaCha20Poly1305Test {
        key:       "047c7d378fe80c02ee48df6f679a859253aed534fdcdd87023eb3d2f93fcafe3",
        nonce:     "ed240b0ff6f8ac585b3ea1ab2dab8080fc2f6401b010c5d0",
        plaintext: "7288afb4e0fa5c58602090a75c10d84b5f5f1c0e03498519afe457251aa7",
        aad:       "e4310302",
        out:       "87906b14ca3e32ab01523b31ae0bb74590ce9e1df0811e743a2c7a93415a",
        tag:       "3a0abeab93792b1ffe768d316da74741",
    },
    XChaCha20Poly1305Test {
        key:       "1ad4e42acc5dfd07eb0a2456e9103cd0e150a36c667eb2f2b73c0d1ac1089ce3",
        nonce:     "48efb52387284c5d38b4940c75f0c39a3f81f60bfebb48cb",
        plaintext: "da7edb5b3193b4484f09efa85fcf85600968ecdc537d3829a469c866ee67b0df677866",
        aad:       "446be8e3",
        out:       "b76457ca99e95b6539b12f1d6bdac55a6d5c6469b1ff274459363ec05241f7e6e5d3ce",
        tag:       "06880ee508ce929da5a81f8b9de0031c",
    },
    XChaCha20Poly1305Test {
        key:       "702a554c1b703d4dd69ad51234293ab787a01e15bdb3ce88bf89e18c01a67164",
        nonce:     "ea535d9c371241b9850b8b4a596b63db79eea60bd2cd9fbb",
        plaintext: "a97156e9b39d05c00b811552d22088d7ee090a117a7f08adac574820d592021f16207720d49fb5fd",
        aad:       "ba5790e3",
        out:       "8d0b2b04479c33287096f0c6276a73f6c037edc1a2b28f8d3b2b8e6d4c5f9dc5113309dd3ecb15e6",
        tag:       "3cf303305e12924d29c223976699fb73",
    },
    XChaCha20Poly1305Test {
        key:       "1bb7303fefa4d8d344bb9a215901b2314324bf1f3aeb9df5d1c1532c3a55ebf1",
        nonce:     "a304551e5f0dc98995ddfee6215a9995023a3696debfd302",
        plaintext: "6cf6819ce3e7ed9d4f85f4a5699701dbcaf3161adc210c0b7825ddfd83d6d7c685db62f68b3801ccc8a786066d",
        aad:       "901c5feb",
        out:       "bc5ef09c111f76e54f897e6fce4aee1d25b6ed934f641ed5262d0c5eed45f610a6aea3b58b7771e34256d43a16",
        tag:       "b83f73f7995ba1b243dbf48ddfeb8e3a",
    },
    XChaCha20Poly1305Test {
        key:       "24b294f6cbac10d87158d1c6aca83b337d596132afac7633f69a3b3e58823f11",
        nonce:     "805772ff619cc6fcc5ec0e9965435d6f74a2290c055ec754",
        plaintext: "65e8581286868caabcec1a9814db00b805edc660b94ee3babc6ce19a3ca868bd322105484d59b4ce02ced4071bc16642a1f2",
        aad:       "7ae1c561",
        out:       "fe1d463b1466e8e411f0b0700f90760472ee5141f3e5afef43fd729f1623dca75cd4d00576765b335f8b2b77b00527599cb3",
        tag:       "111d8540fd5ec04b9ba16ed810133026",
    },
    XChaCha20Poly1305Test {
        key:       "38e63e8b6402ac3f6d1641a1e3b74d2074be0fe41129975a3ff62b74ca52af05",
        nonce:     "228d671b036710cbdaa72e9bf1d9ed6982b0bb3428a69fd6",
        plaintext: "20a8d18878924d09aac32853c10e73dbd741134b7050ae6999839f2dbc727cb0052b5497c4bbd2a89e716278f15c81b871953614a49693",
        aad:       "e9e6ac73",
        out:       "80e0fe8eb26e5df229c6d939c944d440a37aa3cabf76eab5b9a420095513021ea4241ab367f6f44a20817b14631549ae6c96aa963970e1",
        tag:       "1e80fbafcc7168e0494fce4cd76d692c",
    },
    XChaCha20Poly1305Test {
        key:       "4325dd8406fdb8431a81f1b5db3603995256de36121019724cca2190c87a6e83",
        nonce:     "dcbf3077b36d5d678d668fd2d0c99284c780b55c4658ea75",
        plaintext: "4f599ad04f79be9add10fdc649b8be53e1062ea5e9c2bed22265dc6fb30d5ab4fd4425b38ff14d8e68013405bec1eff8c9ef3069902e492aac73dcd9",
        aad:       "6fa0d757",
        out:       "7decbdc7043495c59ecc64e720436bb0708b586a46f8745f74391477f5a2520905dfcebc3765a330999013d309dfaa997bf70bab6a0b8f4f2a2a3cdf",
        tag:       "051ec4ecce208d9be0cd17f434e13be3",
    },
    XChaCha20Poly1305Test {
        key:       "2d3d9ed4bc9eb9668733bafbb73e88be2cd17021c3a23be69b981d9f0df71df1",
        nonce:     "84cae69639240c82b58895997511f145e474ebe1b008f391",
        plaintext: "",
        aad:       "64db597c26a4c3da",
        out:       "",
        tag:       "2a22c4a962d46a719014ab7b0ffaf6d3",
    },
    XChaCha20Poly1305Test {
        key:       "09ec4e79a02db53b19b54dd2d3592afc92c74ef57d1e0f51f3726a6631b1b73f",
        nonce:     "2907ced16e0777fedb1e2de30df11b3fd712af41dd714a4b",
        plaintext: "b6e50cd4ea",
        aad:       "b5488e9b7f339b7b",
        out:       "0163e75330",
        tag:       "e29401c6d756adcc516580ae656852aa",
    },
    XChaCha20Poly1305Test {
        key:       "9d5ac25a417b8a57b85332979e8a7cbad23617bb27772bbccc2acb0acae7b755",
        nonce:     "ff152421688dd6af7fef87817b508493a32d97a06fbda4f3",
        plaintext: "92f4b9bc809be77e6a0d",
        aad:       "892b793f7a6e0727",
        out:       "bcc594f59de8ee8c22c6",
        tag:       "1a8275816c0d32a1b6cfd41fa3889558",
    },
    XChaCha20Poly1305Test {
        key:       "eccf80c5f744d2ecc932f95ade0d9fe9327e19795023db1846d68d04720a2401",
        nonce:     "abc050fad8876589633b222d6a0f2e0bf709f73610aa23ee",
        plaintext: "45a380e438405314510c166bac6840",
        aad:       "c32c9a1ce6852046",
        out:       "9fa452dc9ca04c16ff7bde9925e246",
        tag:       "3d5e826162fa78de3fc043af26044a08",
    },
    XChaCha20Poly1305Test {
        key:       "b1912d6bc3cff47f0c3beccff85d7cd915b70ab88d0d3a8a59e994e1b0da8ac8",
        nonce:     "d8756090a42eea14ff25be890e66bfe4949fad498776ea20",
        plaintext: "e2f85df2ebcfa6045bd521abfe8af37fc88a0be1",
        aad:       "4576bb59b78032c8",
        out:       "5eb6324aa48e0a4f72f5cb0a4917faf93af4209c",
        tag:       "774f8077f039588495045fee07950e14",
    },
    XChaCha20Poly1305Test {
        key:       "85162b111c9f3163f57c2cbc311a1e9aeed9dd6136b5784bc9c0b5052f8bffbd",
        nonce:     "23cdb8b546bb8a5a746b24446f0ab4199f0543d915ff51f1",
        plaintext: "dc81000077d5743beef09ac91663885d984212bbccf3dbe6f3",
        aad:       "3084f3e9c4d0a15f",
        out:       "692d17ae0b524ec6edc0cf49b69ac90c99bed44691f7ae63b7",
        tag:       "efe72ff84b3bccb4d83a27ddc574bc21",
    },
    XChaCha20Poly1305Test {
        key:       "b05ca358d8ca79f51283d83e2673bfb741c379ba271a773b8dd9c6a108e758d3",
        nonce:     "9a53ad79f535c6e9da011463063c896f2ec7645e6e3548fc",
        plaintext: "44e793742c774020e7349c996418042dc0dc30ee2bfd2654008c8929a436",
        aad:       "71ab5948c5e0f4c6",
        out:       "c5eddb7aeaa175b5f3dab68cf746f2acaf56fc62b29804629e25e2d63879",
        tag:       "bec3b7a8b8dad22ff3d14d26273294d2",
    },
    XChaCha20Poly1305Test {
        key:       "abb5136a01354c765a96e832df58bec3b088bd19dc4d6bd6674f2f02007ebdaa",
        nonce:     "71267ac9f4fe5caa1d52cd85948a170a778f0141d54dbffe",
        plaintext: "afb526fe41c4e2a767ce77c4145b9d054268f5f3b279237dec97f8bc46f9d158868b86",
        aad:       "047baa2b04748b62",
        out:       "0032d4c1e65da2266539464c5d3c2b1618454a6af0e7f1e3cfc87845c75f2f4ae8b03f",
        tag:       "b526a95a33f17ab61f2cdfc1e2dd486a",
    },
    XChaCha20Poly1305Test {
        key:       "bb826ed38008a0d7fb34c0c1a1a1149d2cad16b691d5129cc83f5eff2b3e5748",
        nonce:     "4e02fe0915d81e9d5a62e5b3551b9db882e3873c0aaa230d",
        plaintext: "20270d291a8d9791b0f5e35a64387bb4237bad61169841d7e1667c994ad49869c7d5580ffa752a2d",
        aad:       "db852a275081e29b",
        out:       "d740012efb7e1bb986ce2c535134a45f658b92163c109bdecf1ce5b836879fe9e006a56be1fac8d7",
        tag:       "21e931042e7df80695262198a06286c9",
    },
    XChaCha20Poly1305Test {
        key:       "938d2c59f6f3e2e7316726537932372e05e8c1b5577aae0ee870bf712ff001ab",
        nonce:     "fb4d71cf7eb2f70df9759a64c76a36b75203f88bf64f4edb",
        plaintext: "8910415d674a93c54c8f5e4aa88e59648d9a0a5039a66837d58ab14f0665a5f6d9af9b839f9033d0fe8bc58f19",
        aad:       "a3fca278a63bf944",
        out:       "1905c6987a702980b7f87f1ed2d3ae073abe1401b23434f3db43b5c37c979c2068ce9a92afedcdc218003848ea",
        tag:       "1bd712f64777381f68be5ccc73f364a3",
    },
    XChaCha20Poly1305Test {
        key:       "dd0521842f498d23236692a22db0eb2f0f14fef57577e5fb194503e206b0973d",
        nonce:     "519e0eee8f86c75c7a364e0905a5d10d82073e11b91083a5",
        plaintext: "61ff13acb99c5a7fd1921ec787c8de23c1a712ff002b08cecc644a78c47341eab78e7680380c93c7d53d5e56ef050d6ff192",
        aad:       "bb5c4e5ae8f7e461",
        out:       "9bfdb0fd195fa5d37da3416b3b1e8f67bd2a456eb0317c02aabf9aac9d833a19bda299e6388e7b7119be235761477a34d49e",
        tag:       "0f0c03b8423583cb8305a74f622fa1f9",
    },
    XChaCha20Poly1305Test {
        key:       "189bd84be3fb02723539b29cf76d41507c8b85b7217777ee1fb8f84a24aa7fee",
        nonce:     "ef1bf39f22ba2edf86853505c24fafdf62c1a067963c63ba",
        plaintext: "d5f96e240b5dd77b9fb2bf11c154fcbff312a791c3eb0717684e4fd84bf943e788050b47e76c427f42f3e5344b2636091603ba3b1d7a91",
        aad:       "93368a8e0900c7b6",
        out:       "c55a8b7f587bee4f97514582c5115582abffd6312914d76c2568be6836f62ba098789ed897c9a7508a5dc214bf8c218664f29941ccdfd6",
        tag:       "78f87352dcb1143038c95dc6e7352cfd",
    },
    XChaCha20Poly1305Test {
        key:       "23a2dbfcd02d265805169fa86e6927c7d49c9a24d2707884e18955e32dafc542",
        nonce:     "305c7851f46f23ea8d832d5ed09d266714fd14f82ba0f69c",
        plaintext: "224de94a938d49cad46144e657e548bd86690a1b57b81558095eace59df1c552600dea389aaa609304fbc1eadf2241f2118c8bdf04522e1898efe1d4",
        aad:       "0075b20502bd29b2",
        out:       "8e10c59369bbb0d72958100b05788498f59588795e075b8bce21d92d320206348b04010ced9b8cd3d651e825488915ce4a6e4f1af2f4d2f77b955376",
        tag:       "c39f0595ae8112dea6ef96df1c12458b",
    },
    XChaCha20Poly1305Test {
        key:       "264e3c3f47bdf795cdde57d9a30be5a4da8b18463c0e3e05df28b7bf4e56410b",
        nonce:     "3ee09b6e205c261bf48ac53a9ba0afa460a5d5c0f2d80be8",
        plaintext: "",
        aad:       "8eeec09d8972cb8ab0069554",
        out:       "",
        tag:       "245a034d84edab9fa6f0decb6b984766",
    },
    XChaCha20Poly1305Test {
        key:       "d8ba98a272b5f91797b04b114311c3b92b7f2e3bb72edb7f78ed311b9f8ea2ad",
        nonce:     "481de9a06eee76a501e3c2b9d7423d90596193ad9d8a6564",
        plaintext: "9ee1a3134d",
        aad:       "928653701f6d6c8429b08c0d",
        out:       "459a07898f",
        tag:       "9188ec8d8e3bd91dcfda48fcc76773f7",
    },
    XChaCha20Poly1305Test {
        key:       "ac9afd627a745df682bb003517056f07876eb94d2f8c610c61b6ac0d34ec4ec0",
        nonce:     "eaae7b8704530db1e8c3dcc968a00604a333c7c27ba51b16",
        plaintext: "f7c3f6ee2e9c03394dc8",
        aad:       "796620b367d5f041821baf69",
        out:       "d4a69005790cc91d8d34",
        tag:       "e4c83def113afcf83a1ea8cb204a0eae",
    },
    XChaCha20Poly1305Test {
        key:       "ea1a07c1fd60a5421f1fb6c43b4318090e290c97aa3bfa037e6fc5ee00fd47d4",
        nonce:     "37327805cce92b38a669affbca1de92e068727fcf6fbb09a",
        plaintext: "7002ca765b91913ee719e7521ef5ac",
        aad:       "64e7c48fc3041eac0734737f",
        out:       "9d8857a8c52a9ab3bf44b024b191b6",
        tag:       "d072c31714a7d0fe1596fd443a96e715",
    },
    XChaCha20Poly1305Test {
        key:       "b3beb34fe0229fc8f49b354e941025bde6a788f25017a60e8a49591ed5d7e7da",
        nonce:     "dd0e9fec76de1f6efb022b12164f7e9248b8e8c01d14ac02",
        plaintext: "acf360d7529a42be1f132f74745a940da9e823f2",
        aad:       "1489ca8d852f0a8547dbe8bc",
        out:       "2e8718372d6e8167213cf112dc41c80377244f5a",
        tag:       "e4f31e8f84b9356999dc60989009e698",
    },
    XChaCha20Poly1305Test {
        key:       "9357cecd10bab8d2e42ed88c0386204827c3b76e9e51150d09fd4e3b4e0e1e6f",
        nonce:     "81f2106a5379e0ed861cf76b3cf95afb17515478b5cbcae9",
        plaintext: "ee51a0f25d091288b5e2b91ad11d491329e48b35a18a3a8685",
        aad:       "b80cb677f4b409cd1537363b",
        out:       "f681f19fa8de1fdea3538001a46f30fa6333b76d6439337e68",
        tag:       "afad5e6d282d9df6d8119c32237b3e60",
    },
    XChaCha20Poly1305Test {
        key:       "9f868600fbf81e40398b7dfb201fcae35d34bba10908860b0b2bf8b942b4e8fa",
        nonce:     "2ddcc13c97185614095d437900b8c0a9170e0a4a50e46ba5",
        plaintext: "133fa3ac176fee6df67472752e41c6834f13300c0064ff5b190f903b7ac7",
        aad:       "0d61321fbee8bb1f3f5cb454",
        out:       "b93abb311ec0bf018dc300c7d511b42ade72780373186e231820b44f22f0",
        tag:       "f8bd2f649a337783ff911e37966037bd",
    },
    XChaCha20Poly1305Test {
        key:       "05affcdfce0a28539924370db8d80a78b835254778ec41acbff52bfab092fa33",
        nonce:     "3edaeb185f7273b1a7cccba54f84c5f7d6583433b49d3694",
        plaintext: "7657581faad266cc1037962a380c8aa5306f88000427d0a05397696b503790ad2643c6",
        aad:       "d7c213e9e6f4a40f3e5b662c",
        out:       "5eb19080aadc89f2329da4f5c41dc60568651c424c1b05d827f2bfb8dbff42c5a08224",
        tag:       "2da20087b5674f0b967d1baa664bbd82",
    },
    XChaCha20Poly1305Test {
        key:       "645ed60ec74ddfe1f02694792db4436c262d20405d8645cd9755d64876219799",
        nonce:     "d83665b44c1fdf567299f2b8501e9c0e7ae2dda0bb8f2c82",
        plaintext: "ceee69d32ad4667a00909964d9611bf34fd98be41ad7f0feaaaff8169060d64cf310c13bcb9394cf",
        aad:       "57379f8f44191ec9cf3b1a07",
        out:       "4496a0666f0f895ebce224b448a04502f2ae7b354d868b7c54295bf051162e82c530c767d1ffd2cc",
        tag:       "1ffc56da4fb961ffdfabe66d82ec8f29",
    },
    XChaCha20Poly1305Test {
        key:       "06624c9a75bb7dbe224a3f23791281f53c40b407a14161a3f82f34924623dc02",
        nonce:     "e647b8b4739bf542a81d72d695e1cd6ba348fa593987ac47",
        plaintext: "2658763f8d70e8c3303582d66ba3d736ce9d407e9507f6c6627e382d0144da157d73d0aee10ef034083cdd9013",
        aad:       "75536443a6c2189a57d553bb",
        out:       "305cab5c2f9a6edccac307d6965febe3c86f2a1e31ac8c74e88924a10c2a29106bce980c803b7886985bba8ec5",
        tag:       "8c12bb58c84175b9f601b704d0f8a25c",
    },
    XChaCha20Poly1305Test {
        key:       "63aeb46083100bbcc430f4f09bcc34410df9cfd5883d629e4af8645ffabb89c2",
        nonce:     "b09830874dc549195a5d6da93b9dcc12aa1ec8af201c96bd",
        plaintext: "1b3c9050e0a062f5a5cff7bec8706864cf8648142ec5cb1f9867ace384e9b2bba33aab8dc83e83b2d2fac70cd5189f2b5ab5",
        aad:       "7dcc05b0940198bd5c68cdf1",
        out:       "d8b22e5d381de08a50b163c00dbbca6c07d61c80199cebd52234c7bd4f7ed0a90d47ef05617cdb8e3f782875ae629c0f0ad6",
        tag:       "194077f0e6d415bf7307d171e8484a9c",
    },
    XChaCha20Poly1305Test {
        key:       "4826c1bf8b48088fece4008922173c500ff45790f945b1027f36110da4fecc92",
        nonce:     "3a78fc7397944d762303b0a75974ac92a60e250bf112600a",
        plaintext: "d26e3a2b92120ff8056bb992660cc8a2364792589c16a518b8d232b8184aed05ba8d4fd0b2ad2b928cd873e11905a21ffece5f1e63c974",
        aad:       "904d2cd3e50f7bfb9352f142",
        out:       "21f4cf679662fad36f57945fc0c0753c3791261eb58d643278dfe1f14bfb585c5a01370ba96f18dc3f6b6945a2c6997330b24f12f5219a",
        tag:       "95397c54428f9d069c511b5c82e0151c",
    },
    XChaCha20Poly1305Test {
        key:       "ec526c03d8a08e8a63751112428a76399c399e8b83d98c9247c73164805ac8fe",
        nonce:     "2cc1a6ae89c2a091415fa2964b44a0e5da629d40d77b77f1",
        plaintext: "567377f5b6df5442e70bc9a31bc450bd4febfcf89d7ca611353c7e612d8b7e36e859f6365ec7e5e99e9e0e882532666dd7203d06f6e25439ed871237",
        aad:       "35575b56716868b66cd21e24",
        out:       "6b738274fe974438f1f5fca8ef1ee7df664f1e72bc54ccd3fb58c4a3df67ef9a73261df41ffe9c52aeafc8be4f6524baf9efb1558d4a57defec7bee3",
        tag:       "92599d4b14a795e8c375ec2a8960b4dc",
    },
];
