//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP
#define CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>

#include <nil/crypto3/hash/detail/nop_finalizer.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            /*!
             * @brief
             * @tparam DigestEndian
             * @tparam DigestBits
             * @tparam IV
             * @tparam Compressor
             * @tparam Finalizer
             *
             * The Sponge construction builds a block hashes from a
             * one-way compressor.  As this version operated on the block
             * level, it doesn't contain any padding or other strengthening.
             * For a Wide Pipe construction, use a digest that will
             * truncate the internal state.
             */
            template<typename Params,
                     typename IV,  // Seems redundant, no one using it
                     typename Permutation,
                     typename Padding>
            class sponge_construction {
            public:
                typedef IV iv_generator;
                typedef Permutation permutation_functor;
                typedef Padding padding;

                typedef typename Params::digest_endian endian_type;

                constexpr static const std::size_t word_bits = compressor::word_bits;
                typedef typename compressor::word_type word_type;

                // S = R || C (state)
                constexpr static const std::size_t state_bits = compressor::state_bits;
                constexpr static const std::size_t state_words = compressor::state_words;
                typedef typename compressor::state_type state_type;

                // R (bitrate)
                constexpr static const std::size_t block_bits = compressor::block_bits;
                constexpr static const std::size_t block_words = compressor::block_words;
                typedef typename compressor::block_type block_type;

                constexpr static const std::size_t digest_bits = Params::digest_bits;
                constexpr static const std::size_t digest_bytes = digest_bits / octet_bits;
                constexpr static const std::size_t digest_words = digest_bits / word_bits;
                typedef static_digest<digest_bits> digest_type;

                inline digest_type digest(const block_type &block = block_type(),
                                          std::size_t block_bits_filled = std::size_t()) {
                    // TODO: After this call construction will become unusable in case if digest lenght is not divisible by block length (aka bitrate)
                    //       Thus, throwing an error if user tries to use construction afterwards, makes sense.
                    using namespace nil::crypto3::detail;

                    if (block_bits_filled != 0) {
                        block_bits_filled == block_bits ? absorb(block) : absorb_with_padding(block, block_bits_filled);
                    }

                    state_type squeezed_blocks_holder;
                    for (std::size_t i = 0; i < digest_words / block_words + (digest_words % block_words == 0 ? 0 : 1); ++i) {
                        squeezed_blocks_holder[i] = squeeze();
                    }
                    // Convert digest to byte representation
                    digest_type d;
                    pack_from<endian_type, word_bits, octet_bits>(squeezed_blocks_holder.begin(), squeezed_blocks_holder.begin() + digest_words,
                                                                  d.begin());
                    return d;
                }

                inline sponge_construction &absorb(const block_type &block) {
                    for (std::size_t i = 0; i != block_words; ++i)
                        state[i] ^= block[i];
                    compressor_functor::permute(state_);
                    return *this;
                }

                inline sponge_construction &absorb_with_padding(const block_type &block = block_type(),
                                          const std::size_t last_block_bits_filled = 0) {
                    auto padded_blocks = padding::get_padded_blocks(block, last_block_bits_filled);
                    for (auto& block : padded_blocks) {
                        absorb(std::move(block));
                    }
                    return *this;
                }

                inline block_type squeeze() {
                    block_type block;
                    std::copy(state.begin(), state.begin() + block_words, block.begin());
                    compressor_functor::permute(state_, block);
                    return block;
                }

                sponge_construction() {
                    reset();
                }

                void reset(state_type const &s) {
                    state_ = s;
                }

                void reset() {
                    iv_generator iv;
                    reset(iv());
                }

                state_type const &state() const {
                    return state_;
                }

            private:
                state_type state_;
            };

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_SPONGE_CONSTRUCTION_HPP
