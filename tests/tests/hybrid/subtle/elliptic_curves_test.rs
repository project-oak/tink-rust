// Copyright 2020-2021 The Tink-Rust Authors
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

use lazy_static::lazy_static;
use p256::{elliptic_curve::generic_array::typenum::Unsigned, pkcs8::FromPublicKey};
use serde::Deserialize;
use std::collections::HashSet;
use tink_core::TinkError;
use tink_hybrid::subtle;
use tink_proto::{EcPointFormat, EllipticCurveType};
use tink_tests::{expect_err, hex_string, WycheproofResult};

// The tests are from
// http://google.github.io/end-to-end/api/source/src/javascript/crypto/e2e/ecc/ecdh_testdata.js.src.html.
struct TestEc1 {
    curve: EllipticCurveType,
    pub_x: &'static str,
    pub_y: &'static str,
}

struct TestEc2 {
    curve: EllipticCurveType,
    point_format: EcPointFormat,
    encoded: &'static str,
    x: &'static str,
    y: &'static str,
}

lazy_static! {
    static ref TEST_EC1: Vec<TestEc1> = vec![
        TestEc1 {
            curve: EllipticCurveType::NistP256,
            pub_x: "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            pub_y: "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
        },
        TestEc1 {
            curve: EllipticCurveType::NistP256,
            pub_x: "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae",
            pub_y: "b29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3",
        },
        TestEc1 {
            curve: EllipticCurveType::NistP256,
            pub_x: "df3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed",
            pub_y: "422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4",
        },
        TestEc1 {
            curve: EllipticCurveType::NistP256,
            pub_x: "356c5a444c049a52fee0adeb7e5d82ae5aa83030bfff31bbf8ce2096cf161c4b",
            pub_y: "57d128de8b2a57a094d1a001e572173f96e8866ae352bf29cddaf92fc85b2f92",
        },
        TestEc1 {
            curve: EllipticCurveType::NistP384,
            pub_x: concat!(
                "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272",
                "734466b400091adbf2d68c58e0c50066"
            ),
            pub_y: concat!(
                "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915e",
                "d0905a32b060992b468c64766fc8437a"
            ),
        },
        TestEc1 {
            curve: EllipticCurveType::NistP384,
            pub_x: concat!(
                "30f43fcf2b6b00de53f624f1543090681839717d53c7c955d1d69efaf0349b736",
                "3acb447240101cbb3af6641ce4b88e0"
            ),
            pub_y: concat!(
                "25e46c0c54f0162a77efcc27b6ea792002ae2ba82714299c860857a68153ab62e",
                "525ec0530d81b5aa15897981e858757"
            ),
        },
        TestEc1 {
            curve: EllipticCurveType::NistP521,
            pub_x: concat!(
                "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340",
                "854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2",
                "046d"
            ),
            pub_y: concat!(
                "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b7398",
                "84a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302",
                "f676"
            ),
        },
        TestEc1 {
            curve: EllipticCurveType::NistP521,
            pub_x: concat!(
                "000001df277c152108349bc34d539ee0cf06b24f5d3500677b4445453ccc21409",
                "453aafb8a72a0be9ebe54d12270aa51b3ab7f316aa5e74a951c5e53f74cd95fc29a",
                "ee7a"
            ),
            pub_y: concat!(
                "0000013d52f33a9f3c14384d1587fa8abe7aed74bc33749ad9c570b471776422c",
                "7d4505d9b0a96b3bfac041e4c6a6990ae7f700e5b4a6640229112deafa0cd8bb0d0",
                "89b0"
            ),
        },
        TestEc1 {
            curve: EllipticCurveType::NistP521,
            pub_x: concat!(
                "00000092db3142564d27a5f0006f819908fba1b85038a5bc2509906a497daac67",
                "fd7aee0fc2daba4e4334eeaef0e0019204b471cd88024f82115d8149cc0cf4f7ce1",
                "a4d5"
            ),
            pub_y: concat!(
                "0000016bad0623f517b158d9881841d2571efbad63f85cbe2e581960c5d670601",
                "a6760272675a548996217e4ab2b8ebce31d71fca63fcc3c08e91c1d8edd91cf6fe8",
                "45f8"
            ),
        },
        TestEc1 {
            curve: EllipticCurveType::NistP521,
            pub_x: concat!(
                "0000004f38816681771289ce0cb83a5e29a1ab06fc91f786994b23708ff08a08a",
                "0f675b809ae99e9f9967eb1a49f196057d69e50d6dedb4dd2d9a81c02bdcc8f7f51",
                "8460"
            ),
            pub_y: concat!(
                "0000009efb244c8b91087de1eed766500f0e81530752d469256ef79f6b965d8a2",
                "232a0c2dbc4e8e1d09214bab38485be6e357c4200d073b52f04e4a16fc6f5247187",
                "aecb"
            ),
        },
        TestEc1 {
            curve: EllipticCurveType::NistP521,
            pub_x: concat!(
                "000001a32099b02c0bd85371f60b0dd20890e6c7af048c8179890fda308b359db",
                "bc2b7a832bb8c6526c4af99a7ea3f0b3cb96ae1eb7684132795c478ad6f962e4a6f",
                "446d"
            ),
            pub_y: concat!(
                "0000017627357b39e9d7632a1370b3e93c1afb5c851b910eb4ead0c9d387df67c",
                "de85003e0e427552f1cd09059aad0262e235cce5fba8cedc4fdc1463da76dcd4b6d",
                "1a46"
            ),
        },
    ];

    static ref TEST_EC2: Vec<TestEc2> = vec![
        // NIST_P256
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "04",
                "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a",
                "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7"
            ),
            x: "79974177209371530366349631093481213364328002500948308276357601809416549347930",
            y: "11093679777528052772423074391650378811758820120351664471899251711300542565879",
        },
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::DoNotUseCrunchyUncompressed,
            encoded: concat!(
                "b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a",
                "1886ccdca5487a6772f9401888203f90587cc00a730e2b83d5c6f89b3b568df7"
            ),
            x: "79974177209371530366349631093481213364328002500948308276357601809416549347930",
            y: "11093679777528052772423074391650378811758820120351664471899251711300542565879",
        },
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::Compressed,
            encoded: "03b0cfc7bc02fc980d858077552947ffb449b10df8949dee4e56fe21e016dcb25a",
            x: "79974177209371530366349631093481213364328002500948308276357601809416549347930",
            y: "11093679777528052772423074391650378811758820120351664471899251711300542565879",
        },
        // Exceptional point: x==0
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "04",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
            ),
            x: "0",
            y: "46263761741508638697010950048709651021688891777877937875096931459006746039284",
        },
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::DoNotUseCrunchyUncompressed,
            encoded: concat!(
                "0000000000000000000000000000000000000000000000000000000000000000",
                "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
            ),
            x: "0",
            y: "46263761741508638697010950048709651021688891777877937875096931459006746039284",
        },
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::Compressed,
            encoded: "020000000000000000000000000000000000000000000000000000000000000000",
            x: "0",
            y: "46263761741508638697010950048709651021688891777877937875096931459006746039284",
        },
        // Exceptional point: x==-3
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "04",
                "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121"
            ),
            x: "115792089210356248762697446949407573530086143415290314195533631308867097853948",
            y: "11508551065151498768481026661199445482476508121209842448718573150489103679777",
        },
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::DoNotUseCrunchyUncompressed,
            encoded: concat!(
                "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                "19719bebf6aea13f25c96dfd7c71f5225d4c8fc09eb5a0ab9f39e9178e55c121"
            ),
            x: "115792089210356248762697446949407573530086143415290314195533631308867097853948",
            y: "11508551065151498768481026661199445482476508121209842448718573150489103679777",
        },
        TestEc2 {
            curve: EllipticCurveType::NistP256,
            point_format: EcPointFormat::Compressed,
            encoded: "03ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
            x: "115792089210356248762697446949407573530086143415290314195533631308867097853948",
            y: "11508551065151498768481026661199445482476508121209842448718573150489103679777",
        },
        // NIST_P384
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a",
                "385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc",
                "29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e",
                "5f"
            ),
            x: concat!(
                "2624703509579968926862315674456698189185292349110921338781561590",
                "0925518854738050089022388053975719786650872476732087"
            ),
            y: concat!(
                "8325710961489029985546751289520108179287853048861315594709205902",
                "480503199884419224438643760392947333078086511627871"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a",
                "385502f25dbf55296c3a545e3872760ab7"
            ),
            x: concat!(
                "2624703509579968926862315674456698189185292349110921338781561590",
                "0925518854738050089022388053975719786650872476732087"
            ),
            y: concat!(
                "8325710961489029985546751289520108179287853048861315594709205902",
                "480503199884419224438643760392947333078086511627871"
            ),
        },
        // x = 0
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "0400000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000003cf99ef04f51a5ea630ba3f9f960dd",
                "593a14c9be39fd2bd215d3b4b08aaaf86bbf927f2c46e52ab06fb742b8850e52",
                "1e"
            ),
            x: "0",
            y: concat!(
                "9384923975005507693384933751151973636103286582194273515051780595",
                "652610803541482195894618304099771370981414591681054"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "0200000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000"
            ),
            x: "0",
            y: concat!(
                "9384923975005507693384933751151973636103286582194273515051780595",
                "652610803541482195894618304099771370981414591681054"
            ),
        },
        // x = 2
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "0400000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000002732152442fb6ee5c3e6ce1d920c059",
                "bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfd",
                "b3"
            ),
            x: "2",
            y: concat!(
                "1772015366480916228638409476801818679957736647795608728422858375",
                "4887974043472116432532980617621641492831213601947059"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "0300000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000002"
            ),
            x: "2",
            y: concat!(
                "1772015366480916228638409476801818679957736647795608728422858375",
                "4887974043472116432532980617621641492831213601947059"
            ),
        },
        // x = -3
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "04ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "feffffffff0000000000000000fffffffc2de9de09a95b74e6b2c430363e1afb",
                "8dff7164987a8cfe0a0d5139250ac02f797f81092a9bdc0e09b574a8f43bf80c",
                "17"
            ),
            x: concat!(
                "3940200619639447921227904010014361380507973927046544666794829340",
                "4245721771496870329047266088258938001861606973112316"
            ),
            y: concat!(
                "7066741234775658874139271223692271325950306561732202191471600407",
                "582071247913794644254895122656050391930754095909911"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP384,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "feffffffff0000000000000000fffffffc"
            ),
            x: concat!(
                "3940200619639447921227904010014361380507973927046544666794829340",
                "4245721771496870329047266088258938001861606973112316"
            ),
            y: concat!(
                "7066741234775658874139271223692271325950306561732202191471600407",
                "582071247913794644254895122656050391930754095909911"
            ),
        },
        // NIST_P521
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b",
                "4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2",
                "e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd",
                "17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94",
                "769fd16650"
            ),
            x: concat!(
                "2661740802050217063228768716723360960729859168756973147706671368",
                "4188029449964278084915450806277719023520942412250655586621571135",
                "45570916814161637315895999846"
            ),
            y: concat!(
                "3757180025770020463545507224491183603594455134769762486694567779",
                "6155444774405563166912344050129455395621444445372894285225856667",
                "29196580810124344277578376784"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b",
                "4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2",
                "e5bd66"
            ),
            x: concat!(
                "2661740802050217063228768716723360960729859168756973147706671368",
                "4188029449964278084915450806277719023520942412250655586621571135",
                "45570916814161637315895999846"
            ),
            y: concat!(
                "3757180025770020463545507224491183603594455134769762486694567779",
                "6155444774405563166912344050129455395621444445372894285225856667",
                "29196580810124344277578376784"
            ),
        },
        // x = 0
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "0400000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00000000d20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896f",
                "ee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440",
                "ae001f4f87"
            ),
            x: "0",
            y: concat!(
                "2816414230262626695230339754503506208598534788872316917808418392",
                "0894686826982898181454171638541149642517061885689521392260532032",
                "30035588176689756661142736775"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "0300000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000"
            ),
            x: "0",
            y: concat!(
                "2816414230262626695230339754503506208598534788872316917808418392",
                "0894686826982898181454171638541149642517061885689521392260532032",
                "30035588176689756661142736775"
            ),
        },
        // x = 1
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "0400000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000010010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03d",
                "f47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c",
                "832e843564"
            ),
            x: "1",
            y: concat!(
                "2265505274322546447629271557184988697103589068170534253193208655",
                "0778100463909972583865730916407864371153050622267306901033104806",
                "9570407113457901669103973732"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "0200000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000001"
            ),
            x: "1",
            y: concat!(
                "2265505274322546447629271557184988697103589068170534253193208655",
                "0778100463909972583865730916407864371153050622267306901033104806",
                "9570407113457901669103973732"
            ),
        },
        // x = 2
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "0400000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "00000200d9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7f",
                "ce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051",
                "d6aa505acf"
            ),
            x: "2",
            y: concat!(
                "2911448509017565583245824537994174021964465504209366849707937264",
                "0417919148200722009442607963590225526059407040161685364728526719",
                "10134103604091376779754756815"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "0300000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000002"
            ),
            x: "2",
            y: concat!(
                "2911448509017565583245824537994174021964465504209366849707937264",
                "0417919148200722009442607963590225526059407040161685364728526719",
                "10134103604091376779754756815"
            ),
        },
        // x = -2
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Uncompressed,
            encoded: concat!(
                "0401ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "fffffd0010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03d",
                "f47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c",
                "832e843564"
            ),
            x: concat!(
                "6864797660130609714981900799081393217269435300143305409394463459",
                "1855431833976560521225596406614545549772963113914808580371219879",
                "99716643812574028291115057149"
            ),
            y: concat!(
                "2265505274322546447629271557184988697103589068170534253193208655",
                "0778100463909972583865730916407864371153050622267306901033104806",
                "9570407113457901669103973732"
            ),
        },
        TestEc2 {
            curve: EllipticCurveType::NistP521,
            point_format: EcPointFormat::Compressed,
            encoded: concat!(
                "0201ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "fffffd"
            ),
            x: concat!(
                "6864797660130609714981900799081393217269435300143305409394463459",
                "1855431833976560521225596406614545549772963113914808580371219879",
                "99716643812574028291115057149"
            ),
            y: concat!(
                "2265505274322546447629271557184988697103589068170534253193208655",
                "0778100463909972583865730916407864371153050622267306901033104806",
                "9570407113457901669103973732"
            ),
        },
    ];
}

#[test]
fn test_point_on_curve() {
    for (i, tc) in TEST_EC1.iter().enumerate() {
        // TODO(#16): support more curves
        if tc.curve != EllipticCurveType::NistP256 {
            continue;
        }
        let x = hex::decode(&tc.pub_x).unwrap();
        let y = hex::decode(&tc.pub_y).unwrap();
        let _pub_key = subtle::EcPublicKey::new(tc.curve, &x, &y).unwrap_or_else(|e| {
            panic!(
                "case {}: failed to convert valid point to public key: {:?}",
                i, e
            )
        });

        let mut ye = y.clone();
        ye[y.len() - 1] ^= 0x01;

        let result = subtle::EcPublicKey::new(tc.curve, &x, &ye);
        expect_err(result, "invalid point");

        let result = subtle::EcPublicKey::new(EllipticCurveType::UnknownCurve, &x, &y);
        expect_err(result, "unsupported curve");
    }
}

#[test]
fn test_encoding_size_in_bytes() {
    assert_eq!(
        subtle::encoding_size_in_bytes(EllipticCurveType::NistP256, EcPointFormat::Compressed)
            .unwrap(),
        1 + 32
    );
    assert_eq!(
        subtle::encoding_size_in_bytes(EllipticCurveType::NistP256, EcPointFormat::Uncompressed)
            .unwrap(),
        1 + 2 * 32
    );
    assert_eq!(
        subtle::encoding_size_in_bytes(
            EllipticCurveType::NistP256,
            EcPointFormat::DoNotUseCrunchyUncompressed
        )
        .unwrap(),
        2 * 32
    );
    assert_eq!(
        subtle::encoding_size_in_bytes(
            EllipticCurveType::NistP256,
            EcPointFormat::DoNotUseCrunchyUncompressed
        )
        .unwrap(),
        2 * 32
    );
    expect_err(
        subtle::encoding_size_in_bytes(EllipticCurveType::UnknownCurve, EcPointFormat::Compressed),
        "unsupported curve",
    );
    expect_err(
        subtle::encoding_size_in_bytes(EllipticCurveType::NistP256, EcPointFormat::UnknownFormat),
        "invalid point format",
    );
}

fn bigint_str_to_bytes(curve: EllipticCurveType, val: &str) -> Vec<u8> {
    let v = num_bigint::BigUint::parse_bytes(val.as_bytes(), 10)
        .unwrap()
        .to_bytes_be();
    let padded_width = match curve {
        EllipticCurveType::NistP256 => {
            p256::elliptic_curve::FieldSize::<p256::NistP256>::to_usize()
        }
        _ => panic!("unsupported curve {:?}", curve),
    };
    let mut result = vec![0; padded_width];
    (&mut result[padded_width - v.len()..]).copy_from_slice(&v);
    result
}

#[test]
fn test_point_encode() {
    for (i, tc) in TEST_EC2.iter().enumerate() {
        // TODO(#16): support more curves
        if tc.curve != EllipticCurveType::NistP256 {
            continue;
        }
        let pub_key = subtle::EcPublicKey::new(
            tc.curve,
            &bigint_str_to_bytes(tc.curve, tc.x),
            &bigint_str_to_bytes(tc.curve, tc.y),
        )
        .unwrap();
        let encoded_point = subtle::point_encode(tc.curve, tc.point_format, &pub_key)
            .unwrap_or_else(|e| panic!("error in point encoding in test case {} : {:?}", i, e,));
        let want = hex::decode(&tc.encoded).unwrap();
        assert_eq!(
            encoded_point, want,
            "mismatch point encoding in test case {}",
            i
        );

        // Check some invalid variants are rejected.
        let result =
            subtle::point_encode(EllipticCurveType::UnknownCurve, tc.point_format, &pub_key);
        expect_err(result, "unsupported curve");
        let result = subtle::point_encode(tc.curve, EcPointFormat::UnknownFormat, &pub_key);
        expect_err(result, "invalid point format");
    }
}

#[test]
fn test_point_decode() {
    for (i, tc) in TEST_EC2.iter().enumerate() {
        // TODO(#16): support more curves
        if tc.curve != EllipticCurveType::NistP256 {
            continue;
        }
        let e = hex::decode(&tc.encoded).unwrap();
        let pub_key = subtle::point_decode(tc.curve, tc.point_format, &e)
            .unwrap_or_else(|e| panic!("error in point decoding in test case {}: {}", i, e,));
        let spub_key = subtle::EcPublicKey::new(
            tc.curve,
            &bigint_str_to_bytes(tc.curve, tc.x),
            &bigint_str_to_bytes(tc.curve, tc.y),
        )
        .unwrap();

        assert_eq!(
            pub_key.x_y_bytes().unwrap(),
            spub_key.x_y_bytes().unwrap(),
            "mismatch point decoding in test case {}",
            i
        );

        // Check some invalid variants are rejected.
        assert!(subtle::point_decode(tc.curve, tc.point_format, &e[1..]).is_err());
        let mut e_mod = e.clone();
        e_mod[0] ^= 0x10;
        assert!(subtle::point_decode(tc.curve, tc.point_format, &e_mod).is_err());
        let result = subtle::point_decode(EllipticCurveType::UnknownCurve, tc.point_format, &e);
        expect_err(result, "unsupported curve");
        let result = subtle::point_decode(tc.curve, EcPointFormat::UnknownFormat, &e);
        expect_err(result, "invalid point format");
    }
}

#[test]
fn test_point_decode_pads() {
    let pub_x =
        hex::decode("00c7defeb1a16236738e9a1123ba621bc8e9a3f2485b3f8ffde7f9ce98f5a8a1").unwrap();
    let pub_y =
        hex::decode("cb338c3912b1792f60c2b06ec5231e2d84b0e596e9b76d419ce105ece3791dbc").unwrap();
    let _priv_d =
        hex::decode("0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a").unwrap();

    let pub_key = subtle::EcPublicKey::new(EllipticCurveType::NistP256, &pub_x, &pub_y).unwrap();
    let (x, y) = pub_key.x_y_bytes().unwrap();

    // Point parsing allows for zero bytes at the start (e.g. for x coord) to be skipped.
    let pub_key2 =
        subtle::EcPublicKey::new(EllipticCurveType::NistP256, &pub_x[1..], &pub_y).unwrap();
    let (x2, y2) = pub_key2.x_y_bytes().unwrap();
    assert_eq!((x.clone(), y.clone()), (x2, y2));

    // Point parsing allows for extra zero bytes at the start.
    let mut padded_x = vec![0, 0];
    padded_x.extend_from_slice(&pub_x);
    let pub_key3 =
        subtle::EcPublicKey::new(EllipticCurveType::NistP256, &padded_x, &pub_y).unwrap();
    let (x3, y3) = pub_key3.x_y_bytes().unwrap();
    assert_eq!((x, y), (x3, y3));

    // Prefixing with non-zero bytes is a no-no.
    let mut padded_x = vec![0x01];
    padded_x.extend_from_slice(&pub_x);
    expect_err(
        subtle::EcPublicKey::new(EllipticCurveType::NistP256, &padded_x, &pub_y),
        "point too large",
    );
}

fn check_flag(flags: &[String], check: &[&str]) -> bool {
    for f in flags {
        for c in check {
            if f == c {
                return true;
            }
        }
    }
    false
}

/// Converts an encoded public key to a [`subtle::EcPublicKey`].
fn convert_x509_public_key(
    b: &[u8],
    curve: EllipticCurveType,
) -> Result<subtle::EcPublicKey, TinkError> {
    match curve {
        EllipticCurveType::NistP256 => {
            let pub_key = p256::PublicKey::from_public_key_der(b)
                .map_err(|_e| "failed to decode X509 public key")?;
            Ok(subtle::EcPublicKey::NistP256(*pub_key.as_affine()))
        }
        _ => Err(format!("unsupported curve {:?}", curve).into()),
    }
}

/// Convert an EC point public key to an [`subtle::EcPublicKey`].
fn convert_point_public_key(
    pk: &[u8],
    curve: EllipticCurveType,
    flags: &[String],
) -> Result<subtle::EcPublicKey, TinkError> {
    let pt_format = if check_flag(flags, &["CompressedPoint"]) {
        EcPointFormat::Compressed
    } else {
        EcPointFormat::Uncompressed
    };
    subtle::point_decode(curve, pt_format, pk)
}

#[derive(Debug, Deserialize)]
struct EcdhSuite {
    #[serde(flatten)]
    pub suite: tink_tests::WycheproofSuite,
    pub schema: String,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<EcdhGroup>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct EcdhGroup {
    #[serde(flatten)]
    pub group: tink_tests::WycheproofGroup,
    pub curve: String,
    pub encoding: String,
    pub tests: Vec<EcdhCase>,
}

#[derive(Debug, Deserialize)]
struct EcdhCase {
    #[serde(flatten)]
    pub case: tink_tests::WycheproofCase,
    #[serde(with = "hex_string")]
    pub public: Vec<u8>,
    #[serde(with = "hex_string")]
    pub private: Vec<u8>,
    #[serde(with = "hex_string")]
    pub shared: Vec<u8>,
}

#[test]
fn test_ec_wycheproof_cases() {
    for filename in &[
        "ecdh_test.json",
        "ecdh_secp256r1_ecpoint_test.json",
        /* TODO(#16): support more curves
                "ecdh_secp224r1_ecpoint_test.json",
                "ecdh_secp384r1_ecpoint_test.json",
                "ecdh_secp521r1_ecpoint_test.json",
        */
    ] {
        wycheproof_test(filename);
    }
}

fn wycheproof_test(filename: &str) {
    println!("wycheproof file 'testvectors/{}'", filename);
    let bytes = tink_tests::wycheproof_data(&format!("testvectors/{}", filename));
    let data: EcdhSuite = serde_json::from_slice(&bytes).unwrap();
    let mut skipped_curves = HashSet::new();
    for g in &data.test_groups {
        let curve = convert_curve_name(&g.curve);
        // TODO(#16): more ECDSA curves
        // if curve == EllipticCurveType::UnknownCurve {
        if curve != EllipticCurveType::NistP256 {
            if !skipped_curves.contains(&curve) {
                println!("skipping tests for unsupported curve {:?}", curve);
                skipped_curves.insert(curve);
            }
            continue;
        }
        println!("   curve: {:?}", curve);

        for tc in &g.tests {
            let case_name = format!(
                "{}-{}:Case-{}",
                data.suite.algorithm, g.group.group_type, tc.case.case_id
            );
            println!(
                "     case {} [{}] {}",
                tc.case.case_id, tc.case.result, tc.case.comment
            );

            let pvt_key = subtle::EcPrivateKey::new(curve, &tc.private)
                .unwrap_or_else(|e| panic!("{}: failed to parse key: {:?}", case_name, e));
            let pub_key_result = match data.schema.as_str() {
                "ecdh_test_schema.json" => convert_x509_public_key(&tc.public, curve),
                "ecdh_ecpoint_test_schema.json" => {
                    convert_point_public_key(&tc.public, curve, &tc.case.flags)
                }
                _ => panic!("unsupported schema: {}", data.schema),
            };

            match tc.case.result {
                WycheproofResult::Valid => {
                    assert!(
                        pub_key_result.is_ok(),
                        "{}: failed decoding public key: {:?}",
                        case_name,
                        pub_key_result.err()
                    );
                    let pub_key = pub_key_result.unwrap();
                    let shared =
                        subtle::compute_shared_secret(&pub_key, &pvt_key).unwrap_or_else(|e| {
                            panic!("{}: compute_shared_secret() failed: {:?}", case_name, e)
                        });
                    assert_eq!(
                        shared, tc.shared,
                        "{}: valid test case, incorrect shared secret",
                        case_name
                    );
                }
                WycheproofResult::Invalid => {
                    if pub_key_result.is_err() {
                        // Public key not decoded. OK for invalid test case.
                        continue;
                    }
                    let pub_key = pub_key_result.unwrap();
                    let shared_result = subtle::compute_shared_secret(&pub_key, &pvt_key);
                    if shared_result.is_err() {
                        // Shared secret was not computed. OK for invalid test case.
                        continue;
                    }
                    let shared = shared_result.unwrap();
                    let valid_reason = check_flag(
                        &tc.case.flags,
                        &["WrongOrder", "WeakPublicKey", "UnnamedCurve"],
                    );
                    if valid_reason && shared == tc.shared {
                        // accepted invalid parameters but shared secret is correct
                    } else {
                        panic!("{}: accepted invalid parameters", case_name);
                    }
                }
                WycheproofResult::Acceptable => {
                    if pub_key_result.is_err() {
                        // Public key not decoded. OK for acceptable test case.
                        continue;
                    }
                    let pub_key = pub_key_result.unwrap();
                    let shared_result = subtle::compute_shared_secret(&pub_key, &pvt_key);
                    if shared_result.is_err() {
                        // Shared secret was not computed. OK for acceptable test case.
                        continue;
                    }
                    let shared = shared_result.unwrap();
                    assert_eq!(
                        shared, tc.shared,
                        "{}: acceptable test case, incorrect shared secret",
                        case_name
                    );
                }
            }
        }
    }
}

/// Convert different forms of a curve name to the type that Tink recognizes.
pub fn convert_curve_name(name: &str) -> EllipticCurveType {
    match name {
        "secp256r1" | "P-256" => EllipticCurveType::NistP256,
        "secp384r1" | "P-384" => EllipticCurveType::NistP384,
        "secp521r1" | "P-521" => EllipticCurveType::NistP521,
        _ => EllipticCurveType::UnknownCurve,
    }
}
