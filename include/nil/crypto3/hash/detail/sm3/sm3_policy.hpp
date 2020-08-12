//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SM3_POLICY_HPP
#define CRYPTO3_SM3_POLICY_HPP

#include <nil/crypto3/hash/detail/sm3/sm3_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                struct sm3_policy : public sm3_functions {
                    constexpr static const std::size_t word_bits = sm3_functions::word_bits;
                    typedef typename sm3_functions::word_type word_type;

                    constexpr static const std::size_t block_words = 8;
                    constexpr static const std::size_t block_bits = block_words * word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t state_bits = block_bits;
                    constexpr static const std::size_t state_words = block_words;
                    typedef block_type state_type;

                    constexpr static const std::size_t digest_bits = block_bits;
                    typedef static_digest<digest_bits> digest_type;

                    typedef typename stream_endian::little_octet_big_bit digest_endian;

                    constexpr static const std::size_t pkcs_id_size = 18;
                    constexpr static const std::size_t pkcs_id_bits = pkcs_id_size * CHAR_BIT;
                    typedef std::array<std::uint8_t, pkcs_id_size> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x30, 0x30, 0x0C, 0x06, 0x08,
                                                                   0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01,
                                                                   0x83, 0x11, 0x05, 0x00, 0x04, 0x20};

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {{0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL,
                                                                     0xda8a0600UL, 0xa96f30bcUL, 0x163138aaUL,
                                                                     0xe38dee4dUL, 0xb0fb0e4eUL}};
                            return H0;
                        }
                    };
                };

                constexpr typename sm3_policy::pkcs_id_type const
                    sm3_policy::pkcs_id;
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SM3_POLICY_HPP
