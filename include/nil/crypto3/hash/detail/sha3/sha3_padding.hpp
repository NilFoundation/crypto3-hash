//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_SHA3_PADDING_HPP
#define CRYPTO3_SHA3_PADDING_HPP

#include <nil/crypto3/hash/detail/sha3/sha3_policy.hpp>
#include <nil/crypto3/hash/detail/sponge_padding.hpp>
#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>


namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                // pad10*1 scheme
                template<typename Hash>
                class sha3_padding : public sponge_padding_base<sha3_padding, Hash> {{
                    typedef Hash policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    typedef ::nil::crypto3::detail::injector<stream_endian::big_octet_little_bit, word_bits,
                                                             block_words, block_bits>
                        injector_type;

                public:
                    static std::vector<block_type> get_padded_blocks(const block_type& block, std::size_t block_seen) {
                        using namespace nil::crypto3::detail;

                        std::vector<block_type> padded_blocks;
                        block_type new_block = block; // Start with the current block

                        if ((block_bits - block_seen) > 3) {
                            // Typical case when there is enough place for padding
                            // pad 011
                            injector_type::inject(unbounded_shr(high_bits<word_bits>(~word_type(), 2), 5), 3, new_block, block_seen);
                            // pad 0*
                            std::fill(new_block.begin() + (block_seen / (sizeof(word_type) * 8)), new_block.end(), 0);
                            // pad 1
                            injector_type::inject(unbounded_shr(high_bits<word_bits>(~word_type(), 1), 7), 1, new_block, block_seen);

                            padded_blocks.push_back(new_block);
                        } else {
                            // If there's not enough space
                            std::size_t ind = block_bits - block_seen - 1;
                            new_block[block_words - 1] &= ~high_bits<word_bits>(~word_type(), ind + 1);
                            new_block[block_words - 1] |= high_bits<word_bits>(~word_type(), ind);

                            padded_blocks.push_back(new_block);

                            // Create an additional block for the remaining padding
                            block_type extra_block;
                            std::fill(extra_block.begin(), extra_block.end(), 0);

                            // Padding logic for the extra block
                            // pad 1 (since the block is initially all zeros, just set the first bit to 1)
                            injector_type::inject(high_bits<word_bits>(~word_type(), 1), 1, extra_block, 0);

                            padded_blocks.push_back(extra_block);
                        }

                        return padded_blocks;
                    }
                };
            }    // namespace detail
        }    // namespace hashes
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_PADDING_HPP
