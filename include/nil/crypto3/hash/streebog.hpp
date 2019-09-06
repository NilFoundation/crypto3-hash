//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREEBOG_HPP
#define CRYPTO3_STREEBOG_HPP

#include <nil/crypto3/hash/detail/state_adder.hpp>
#include <nil/crypto3/hash/detail/miyaguchi_preneel_compressor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_state_preprocessor.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>

#include <nil/crypto3/hash/detail/streebog/streebog_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @brief Streebog hash compressor
             * @tparam DigestBits
             *
             * @note Actually Streebog is based on Merkle-Damgard construction with
             * Miyaguchi-Preneel compressor, so this should be refactored to miyaguchi_preneel
             * compressor usage with the separate cipher defined.
             */
            template<std::size_t DigestBits>
            class streebog_compressor {
                typedef detail::streebog_policy<DigestBits> policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                void operator()(state_type &state, const block_type &block) {
                    uint64_t N = force_le(last_block ? 0ULL : m_count);

                    uint64_t hN[8];
                    uint64_t A[8];

                    copy_mem(hN, m_h.data(), 8);
                    hN[0] ^= N;
                    lps(hN);

                    copy_mem(A, hN, 8);

                    for (size_t i = 0; i != 8; ++i) {
                        hN[i] ^= M[i];
                    }

                    for (size_t i = 0; i < 12; ++i) {
                        for (size_t j = 0; j != 8; ++j) {
                            A[j] ^= force_le(STREEBOG_C[i][j]);
                        }
                        lps(A);

                        lps(hN);
                        for (size_t j = 0; j != 8; ++j) {
                            hN[j] ^= A[j];
                        }
                    }

                    for (size_t i = 0; i != 8; ++i) {
                        m_h[i] ^= hN[i] ^ M[i];
                    }

                    if (!last_block) {
                        uint64_t carry = 0;
                        for (int i = 0; i < 8; i++) {
                            const uint64_t m = force_le(M[i]);
                            const uint64_t hi = force_le(m_S[i]);
                            const uint64_t t = hi + m;

                            m_S[i] = force_le(t + carry);
                            carry = (t < hi ? 1 : 0) | (t < m ? 1 : 0);
                        }
                    }

                    //                    policy_type::g(state, block);
                    //                    policy_type::addm(block, state);
                }
            };

            template<std::size_t DigestBits>
            class streebog_finalizer {};

            /*!
             * @brief Streebog (GOST R 34.11-2012). RFC 6986. Newly designed Russian
             * national hash function. Due to use of input-dependent table lookups,
             * it is vulnerable to side channels. There is no reason to use it unless
             * compatibility is needed.
             *
             * @ingroup hash
             */
            template<std::size_t DigestBits>
            class streebog {
                typedef detail::streebog_policy<DigestBits> policy_type;

            public:
                typedef merkle_damgard_construction<stream_endian::little_octet_big_bit, policy_type::digest_bits,
                                                    typename policy_type::iv_generator, streebog_compressor<DigestBits>>
                    construction_type;

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = 0;
                    };

                    typedef merkle_damgard_state_preprocessor<construction_type, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename construction_type::digest_type digest_type;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif
