//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_HASH_KECCAK_HPP
#define CRYPTO3_HASH_KECCAK_HPP

#include <nil/crypto3/hash/detail/sponge_construction.hpp>
#include <nil/crypto3/hash/detail/block_stream_processor.hpp>

#include <nil/crypto3/hash/detail/keccak/keccak_functions.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_finalizer.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_padding.hpp>
#include <nil/crypto3/hash/type_traits.hpp>

#include <boost/endian/conversion.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<std::size_t DigestBits = 512>
            class keccak_1600_compressor {
            protected:
                typedef detail::keccak_1600_functions<DigestBits> policy_type;
                typedef typename policy_type::impl_type impl_type;
                typedef typename policy_type::const_impl_type const_impl_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                static constexpr void process_block(state_type &state, const block_type &block) {
                    for (std::size_t i = 0; i != block_words; ++i)
                        state[i] ^= block[i];

                    for (std::size_t i = 0; i != state_words; ++i)
                        boost::endian::endian_reverse_inplace(state[i]);

                    if (!CRYPTO3_IS_CONST_EVALUATED(state)) {
                        impl_type::permute(state);
                    } else {
                        const_impl_type::permute(state);
                    }

                    for (std::size_t i = 0; i != state_words; ++i)
                        boost::endian::endian_reverse_inplace(state[i]);
                }
            };

            /*!
             * @brief
             * @tparam DigestBits
             * @ingroup hashes
             */
            template<std::size_t DigestBits = 512>
            class keccak_1600 {
                typedef detail::keccak_1600_policy<DigestBits> policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                struct construction {
                    struct params_type {
                        typedef typename policy_type::digest_endian digest_endian;

                        constexpr static const std::size_t length_bits = policy_type::length_bits;
                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    };

                    typedef sponge_construction<
                        params_type, typename policy_type::iv_generator, keccak_1600_compressor<DigestBits>,
                        detail::keccak_1600_padding<policy_type>, detail::keccak_1600_finalizer<policy_type>>
                        type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename policy_type::digest_endian digest_endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                    };

                    typedef block_stream_processor<construction, StateAccumulator, params_type> type;
                };
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif
