//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_DETAIL_H2C_FUNCTIONS_HPP
#define CRYPTO3_HASH_DETAIL_H2C_FUNCTIONS_HPP

#include <cstdint>
#include <array>
#include <vector>
#include <iterator>
#include <type_traits>

#include <boost/assert.hpp>
#include <boost/static_assert.hpp>
#include <boost/concept/assert.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/detail/strxor.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/hash/h2c_suites.hpp>
#include <nil/crypto3/hash/detail/h2c/h2c_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldParams>
                inline bool sgn0(const algebra::fields::detail::element_fp<FieldParams> &e) {
                    using modular_type = typename FieldParams::modular_type;

                    static const modular_type two =
                        modular_type(2, algebra::fields::detail::element_fp<FieldParams>::modulus);

                    return static_cast<bool>(e.data % two);
                }

                template<typename FieldParams>
                inline bool sgn0(const algebra::fields::detail::element_fp2<FieldParams> &e) {
                    using underlying_type = typename algebra::fields::detail::element_fp2<FieldParams>::underlying_type;
                    using modular_type = typename FieldParams::modular_type;

                    static const modular_type two = modular_type(2, underlying_type::modulus);

                    modular_type sign_0 = e.data[0].data % two;
                    bool zero_0 = e.data[0].data.is_zero();
                    modular_type sign_1 = e.data[1].data % two;
                    return static_cast<bool>(sign_0) || (zero_0 && static_cast<bool>(sign_1));
                }

                template<typename Group>
                struct iso_map;

                // 11-isogeny map for BLS12-381 G1
                // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-E.2
                template<typename Coordinates, typename Form>
                class iso_map<typename algebra::curves::bls12_381::g1_type<Coordinates, Form>> {
                    typedef typename algebra::curves::bls12_381::g1_type<Coordinates, Form> group_type;
                    typedef h2c_suite<group_type> suite_type;

                    typedef typename suite_type::group_value_type group_value_type;
                    typedef typename suite_type::field_value_type field_value_type;
                    typedef typename suite_type::integral_type integral_type;

                    // TODO: change integral_type on field_value_type when constexpr will be finished
                    constexpr static std::array<integral_type, 12> k_x_num = {
                        0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7_cppui381,
                        0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb_cppui381,
                        0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0_cppui381,
                        0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861_cppui381,
                        0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9_cppui381,
                        0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983_cppui381,
                        0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84_cppui381,
                        0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e_cppui381,
                        0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317_cppui381,
                        0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e_cppui381,
                        0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b_cppui381,
                        0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229_cppui381};

                    constexpr static std::array<integral_type, 10> k_x_den = {
                        0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c_cppui381,
                        0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff_cppui381,
                        0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19_cppui381,
                        0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8_cppui381,
                        0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e_cppui381,
                        0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5_cppui381,
                        0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a_cppui381,
                        0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e_cppui381,
                        0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641_cppui381,
                        0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a_cppui381};

                    constexpr static std::array<integral_type, 16> k_y_num = {
                        0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33_cppui381,
                        0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696_cppui381,
                        0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6_cppui381,
                        0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb_cppui381,
                        0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb_cppui381,
                        0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0_cppui381,
                        0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2_cppui381,
                        0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29_cppui381,
                        0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587_cppui381,
                        0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30_cppui381,
                        0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132_cppui381,
                        0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e_cppui381,
                        0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8_cppui381,
                        0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133_cppui381,
                        0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b_cppui381,
                        0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604_cppui381};

                    constexpr static std::array<integral_type, 15> k_y_den = {
                        0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1_cppui381,
                        0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d_cppui381,
                        0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2_cppui381,
                        0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416_cppui381,
                        0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d_cppui381,
                        0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac_cppui381,
                        0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c_cppui381,
                        0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9_cppui381,
                        0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a_cppui381,
                        0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55_cppui381,
                        0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8_cppui381,
                        0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092_cppui381,
                        0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc_cppui381,
                        0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7_cppui381,
                        0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f_cppui381};

                public:
                    static inline group_value_type process(const group_value_type &ci) {
                        field_value_type x_num = field_value_type::zero();
                        field_value_type x_den = field_value_type::zero();
                        field_value_type y_num = field_value_type::zero();
                        field_value_type y_den = field_value_type::zero();

                        std::vector<field_value_type> xi_powers = [&ci]() {
                            std::vector<field_value_type> xi_powers {field_value_type::one()};
                            for (std::size_t i = 0; i < 15; i++) {
                                xi_powers.emplace_back(xi_powers.back() * ci.X);
                            }
                            return xi_powers;
                        }();

                        for (std::size_t i = 0; i < k_x_den.size(); i++) {
                            x_den += field_value_type(k_x_den[i]) * xi_powers[i];
                        }
                        x_den += xi_powers[k_x_den.size()];

                        for (std::size_t i = 0; i < k_y_den.size(); i++) {
                            y_den += field_value_type(k_y_den[i]) * xi_powers[i];
                        }
                        y_den += xi_powers[k_y_den.size()];

                        if (x_den.is_zero() || y_den.is_zero()) {
                            return group_value_type::one();
                        }

                        for (std::size_t i = 0; i < k_x_num.size(); i++) {
                            x_num += field_value_type(k_x_num[i]) * xi_powers[i];
                        }

                        for (std::size_t i = 0; i < k_y_num.size(); i++) {
                            y_num += field_value_type(k_y_num[i]) * xi_powers[i];
                        }

                        return group_value_type(x_num / x_den, ci.Y * y_num / y_den, field_value_type::one());
                    }
                };

                // 3-isogeny map for BLS12-381 G2
                // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-E.3
                template<typename Coordinates, typename Form>
                class iso_map<typename algebra::curves::bls12_381::g2_type<Coordinates, Form>> {
                    typedef typename algebra::curves::bls12_381::g2_type<Coordinates, Form> group_type;
                    typedef h2c_suite<group_type> suite_type;

                    typedef typename suite_type::group_value_type group_value_type;
                    typedef typename suite_type::field_value_type field_value_type;
                    typedef typename suite_type::integral_type integral_type;

                    // TODO: change integral_type on field_value_type when constexpr will be finished
                    constexpr static std::array<std::array<integral_type, 2>, 4> k_x_num = {
                        {{{0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6_cppui381,
                           0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6_cppui381}},
                         {{0,
                           0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a_cppui381}},
                         {{0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e_cppui381,
                           0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d_cppui381}},
                         {{0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1_cppui381,
                           0}}}};

                    constexpr static std::array<std::array<integral_type, 2>, 2> k_x_den = {
                        {{{0,
                           0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63_cppui381}},
                         {{0xc,
                           0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f_cppui381}}}};

                    constexpr static std::array<std::array<integral_type, 2>, 4> k_y_num = {
                        {{{0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706_cppui381,
                           0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706_cppui381}},
                         {{0,
                           0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be_cppui381}},
                         {{0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c_cppui381,
                           0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f_cppui381}},
                         {{0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10_cppui381,
                           0}}}};

                    constexpr static std::array<std::array<integral_type, 2>, 3> k_y_den = {
                        {{{0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb_cppui381,
                           0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb_cppui381}},
                         {{0,
                           0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3_cppui381}},
                         {{0x12,
                           0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99_cppui381}}}};

                public:
                    static inline group_value_type process(const group_value_type &ci) {
                        field_value_type x_num = field_value_type::zero();
                        field_value_type x_den = field_value_type::zero();
                        field_value_type y_num = field_value_type::zero();
                        field_value_type y_den = field_value_type::zero();

                        std::vector<field_value_type> xi_powers = [&ci]() {
                            std::vector<field_value_type> xi_powers {field_value_type::one()};
                            for (std::size_t i = 0; i < 3; i++) {
                                auto v = xi_powers.back();
                                xi_powers.emplace_back(xi_powers.back() * ci.X);
                            }
                            return xi_powers;
                        }();

                        for (std::size_t i = 0; i < k_x_den.size(); i++) {
                            x_den += field_value_type(k_x_den[i][0], k_x_den[i][1]) * xi_powers[i];
                        }
                        x_den += xi_powers[k_x_den.size()];

                        for (std::size_t i = 0; i < k_y_den.size(); i++) {
                            y_den += field_value_type(k_y_den[i][0], k_y_den[i][1]) * xi_powers[i];
                        }
                        y_den += xi_powers[k_y_den.size()];

                        if (x_den.is_zero() || y_den.is_zero()) {
                            return group_value_type::one();
                        }

                        for (std::size_t i = 0; i < k_x_num.size(); i++) {
                            x_num += field_value_type(k_x_num[i][0], k_x_num[i][1]) * xi_powers[i];
                        }

                        for (std::size_t i = 0; i < k_y_num.size(); i++) {
                            y_num += field_value_type(k_y_num[i][0], k_y_num[i][1]) * xi_powers[i];
                        }

                        return group_value_type(x_num / x_den, ci.Y * y_num / y_den, field_value_type::one());
                    }
                };

                template<typename Group>
                struct m2c_simple_swu {
                    typedef h2c_suite<Group> suite_type;

                    typedef typename suite_type::group_value_type group_value_type;
                    typedef typename suite_type::field_value_type field_value_type;

                    static inline group_value_type process(const field_value_type &u) {
                        // TODO: We assume that Z meets the following criteria -- correct for predefined suites,
                        //  but wrong in general case
                        // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-6.6.2
                        // Preconditions:
                        // 1.  Z is non-square in F,
                        // 2.  Z != -1 in F,
                        // 3.  the polynomial g(x) - Z is irreducible over F, and
                        // 4.  g(B / (Z * A)) is square in F.
                        static const field_value_type one = field_value_type::one();

                        field_value_type tv1 = (suite_type::Z.pow(2) * u.pow(4) + suite_type::Z * u.pow(2)).inversed();
                        field_value_type x1 = (-suite_type::Bi / suite_type::Ai) * (one + tv1);
                        if (tv1.is_zero()) {
                            x1 = suite_type::Bi / (suite_type::Z * suite_type::Ai);
                        }
                        field_value_type gx1 = x1.pow(3) + suite_type::Ai * x1 + suite_type::Bi;
                        field_value_type x2 = suite_type::Z * u.pow(2) * x1;
                        field_value_type gx2 = x2.pow(3) + suite_type::Ai * x2 + suite_type::Bi;
                        field_value_type x, y;
                        if (gx1.is_square()) {
                            x = x1;
                            y = gx1.sqrt();
                        } else {
                            x = x2;
                            y = gx2.sqrt();
                        }
                        if (sgn0(u) != sgn0(y)) {
                            y = -y;
                        }
                        return group_value_type(x, y, one);
                    }
                };

                template<typename Group>
                struct m2c_simple_swu_zeroAB {
                    typedef h2c_suite<Group> suite_type;

                    typedef typename suite_type::group_value_type group_value_type;
                    typedef typename suite_type::field_value_type field_value_type;

                    static inline group_value_type process(const field_value_type &u) {
                        group_value_type ci = m2c_simple_swu<Group>::process(u);
                        return iso_map<Group>::process(ci);
                    }
                };

                template<typename Group>
                struct map_to_curve;

                template<typename Coordinates, typename Form>
                struct map_to_curve<typename algebra::curves::bls12_381::g1_type<Coordinates, Form>>
                    : m2c_simple_swu_zeroAB<typename algebra::curves::bls12_381::g1_type<Coordinates, Form>> { };

                template<typename Coordinates, typename Form>
                struct map_to_curve<typename algebra::curves::bls12_381::g2_type<Coordinates, Form>>
                    : m2c_simple_swu_zeroAB<typename algebra::curves::bls12_381::g2_type<Coordinates, Form>> { };

                template<std::size_t k,
                         std::size_t len_in_bytes,
                         typename Hash,
                         typename PublicParams,
                         /// Hash::digest_type is required to be uint8_t[]
                         typename = typename std::enable_if<
                             std::is_same<std::uint8_t, typename Hash::digest_type::value_type>::value>::type>
                class expand_message_xmd {
                    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
                    static_assert(Hash::block_bits % 8 == 0, "r_in_bytes is not a multiple of 8");
                    static_assert(Hash::digest_bits % 8 == 0, "b_in_bytes is not a multiple of 8");
                    static_assert(Hash::digest_bits >= 2 * k, "k-bit collision resistance is not fulfilled");
                    static_assert(len_in_bytes < 0x10000, "len_in_bytes should be less than 0x10000");

                    constexpr static std::size_t b_in_bytes = Hash::digest_bits / 8;
                    constexpr static std::size_t r_in_bytes = Hash::block_bits / 8;
                    constexpr static std::array<std::uint8_t, 2> l_i_b_str = {
                        static_cast<std::uint8_t>(len_in_bytes >> 8u), static_cast<std::uint8_t>(len_in_bytes % 0x100)};
                    constexpr static std::size_t ell = static_cast<std::size_t>(len_in_bytes / b_in_bytes) +
                                                       static_cast<std::size_t>(len_in_bytes % b_in_bytes != 0);
                    constexpr static const std::array<std::uint8_t, r_in_bytes> Z_pad {0};

                    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-5.4.1
                    static_assert(ell <= 255, "ell should be less than 256");

                public:
                    typedef std::array<std::uint8_t, len_in_bytes> result_type;
                    typedef accumulator_set<Hash> internal_accumulator_type;

                    static inline void init_accumulator(internal_accumulator_type &acc) {
                        hash<Hash>(Z_pad, acc);
                    }

                    template<typename InputRange>
                    static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<InputRange>));

                        hash<Hash>(range, acc);
                    }

                    template<typename InputIterator>
                    static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        hash<Hash>(first, last, acc);
                    }

                    static inline result_type process(internal_accumulator_type &b0_acc) {
                        auto dst_size = std::distance(std::cbegin(PublicParams::dst), std::cend(PublicParams::dst));
                        assert(dst_size >= 16 && dst_size <= 255);

                        hash<Hash>(l_i_b_str, b0_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {0}, b0_acc);
                        hash<Hash>(PublicParams::dst, b0_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst_size)}, b0_acc);
                        typename Hash::digest_type b0 = ::nil::crypto3::accumulators::extract::hash<Hash>(b0_acc);

                        result_type uniform_bytes;
                        internal_accumulator_type bi_acc;
                        hash<Hash>(b0, bi_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {1}, bi_acc);
                        hash<Hash>(PublicParams::dst, bi_acc);
                        hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst_size)}, bi_acc);
                        typename Hash::digest_type bi = ::nil::crypto3::accumulators::extract::hash<Hash>(bi_acc);
                        std::copy(bi.begin(), bi.end(), uniform_bytes.begin());

                        typename Hash::digest_type xored_b;
                        for (std::size_t i = 2; i <= ell; i++) {
                            internal_accumulator_type bi_acc;
                            ::nil::crypto3::detail::strxor(b0, bi, xored_b.begin());
                            hash<Hash>(xored_b, bi_acc);
                            hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(i)}, bi_acc);
                            hash<Hash>(PublicParams::dst, bi_acc);
                            hash<Hash>(std::array<std::uint8_t, 1> {static_cast<std::uint8_t>(dst_size)}, bi_acc);
                            bi = ::nil::crypto3::accumulators::extract::hash<Hash>(bi_acc);
                            std::copy(bi.begin(), bi.end(), uniform_bytes.begin() + (i - 1) * b_in_bytes);
                        }

                        return uniform_bytes;
                    }
                };

                template<typename Group,
                         typename PublicParams,
                         UniformityCount uniformity_count,
                         ExpandMsgVariant expand_msg_variant = ExpandMsgVariant::rfc_xmd,
                         typename = void>
                struct ep_map;

                template<typename Group,
                         typename PublicParams,
                         UniformityCount uniformity_count,
                         ExpandMsgVariant expand_msg_variant>
                struct ep_map<Group,
                              PublicParams,
                              uniformity_count,
                              expand_msg_variant,
                              typename std::enable_if<    // algebra::is_group_element<typename
                                                          // Group::value_type>::value &&
                                  (ExpandMsgVariant::rfc_xmd == expand_msg_variant)>::type> {
                    typedef h2c_suite<Group> suite_type;

                    typedef typename suite_type::group_value_type group_value_type;
                    typedef typename suite_type::field_type field_type;
                    typedef typename suite_type::field_value_type field_value_type;
                    typedef typename suite_type::modular_type modular_type;
                    typedef typename suite_type::integral_type integral_type;
                    typedef typename suite_type::hash_type hash_type;

                    constexpr static std::size_t digest_bits = hash_type::digest_bits;
                    constexpr static std::size_t modulus_bits = field_type::modulus_bits;

                    constexpr static std::size_t m = suite_type::m;
                    constexpr static std::size_t L = suite_type::L;
                    constexpr static std::size_t k = suite_type::k;
                    constexpr static std::size_t count = static_cast<std::size_t>(uniformity_count);

                    static_assert(count == 1 || count == 2, "unavailable count value");

                    constexpr static std::size_t len_in_bytes = count * m * L;

                    typedef expand_message_xmd<k, len_in_bytes, hash_type, PublicParams> expand_message_type;
                    typedef group_value_type result_type;
                    typedef typename expand_message_type::internal_accumulator_type internal_accumulator_type;

                    static inline void init_accumulator(internal_accumulator_type &acc) {
                        expand_message_type::init_accumulator(acc);
                    }

                    template<typename InputRange>
                    static inline void update(internal_accumulator_type &acc, const InputRange &range) {
                        expand_message_type::update(acc, range);
                    }

                    template<typename InputIterator>
                    static inline void update(internal_accumulator_type &acc, InputIterator first, InputIterator last) {
                        expand_message_type::update(acc, first, last);
                    }

                    // TODO: use type deducing to element_fp instead of arity, make FieldParams public for this
                    template<std::size_t arity = m, typename std::enable_if<1 == arity, bool>::type = true>
                    static inline std::array<field_value_type, count> hash_to_field(internal_accumulator_type &acc) {
                        typename expand_message_type::result_type uniform_bytes = expand_message_type::process(acc);

                        std::array<modular_type, m> coordinates;
                        std::array<field_value_type, count> result;
                        for (std::size_t i = 0; i < count; i++) {
                            for (std::size_t j = 0; j < m; j++) {
                                auto elm_offset = L * (j + i * m);

                                // TODO: creating copy of range is a bottleneck:
                                //  extend marshaling interface by function supporting initialization from
                                //  container which length is less than modulus_octets
                                std::vector<std::uint8_t> imported_octets;
                                std::copy(std::cbegin(uniform_bytes) + elm_offset,
                                          std::cbegin(uniform_bytes) + elm_offset + L,
                                          std::back_inserter(imported_octets));
                                nil::marshalling::status_type status;
                                multiprecision::cpp_int tmp = nil::marshalling::pack<nil::marshalling::option::big_endian>(imported_octets, status);
                                coordinates[j] = modular_type(tmp, suite_type::p);
                            }
                            result[i] = coordinates[0];
                        }

                        return result;
                    }

                    // TODO: use type deducing to element_fp2 instead of arity, make FieldParams public for this
                    template<std::size_t arity = m, typename std::enable_if<2 == arity, bool>::type = true>
                    static inline std::array<field_value_type, count> hash_to_field(internal_accumulator_type &acc) {
                        typename expand_message_type::result_type uniform_bytes = expand_message_type::process(acc);

                        std::array<modular_type, m> coordinates;
                        std::array<field_value_type, count> result;
                        for (std::size_t i = 0; i < count; i++) {
                            for (std::size_t j = 0; j < m; j++) {
                                auto elm_offset = L * (j + i * m);

                                // TODO: creating copy of range is a bottleneck:
                                //  extend marshaling interface by function supporting initialization from
                                //  container which length is less than modulus_octets
                                std::vector<std::uint8_t> imported_octets;
                                std::copy(std::cbegin(uniform_bytes) + elm_offset,
                                          std::cbegin(uniform_bytes) + elm_offset + L,
                                          std::back_inserter(imported_octets));
                                nil::marshalling::status_type status;
                                multiprecision::cpp_int tmp = nil::marshalling::pack<nil::marshalling::option::big_endian>(imported_octets, status);
                                coordinates[j] = modular_type(tmp, suite_type::p);
                            }
                            result[i] = field_value_type(coordinates[0], coordinates[1]);
                        }

                        return result;
                    }

                    static inline group_value_type clear_cofactor(const group_value_type &R) {
                        return R * suite_type::h_eff;
                    }

                    static inline result_type process(internal_accumulator_type &acc) {
                        auto u = hash_to_field(acc);
                        group_value_type Q0 = map_to_curve<Group>::process(u[0]);
                        group_value_type Q1 = map_to_curve<Group>::process(u[1]);
                        return clear_cofactor(Q0 + Q1);
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_H2C_FUNCTIONS_HPP
