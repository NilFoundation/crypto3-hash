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
                template<typename Policy>
                class sha3_padding : public sponge_padding_base<sha3_padding<Policy>, Policy> {
                    typedef Policy policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t bitrate_bits = policy_type::bitrate_bits;
                    constexpr static const std::size_t bitrate_words = policy_type::bitrate_words;
                    typedef typename policy_type::bitrate_type bitrate_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    typedef ::nil::crypto3::detail::injector<stream_endian::big_octet_big_bit, stream_endian::little_octet_little_bit, word_bits,
                                                             bitrate_words>
                        injector_type;

                public:
                    static std::vector<bitrate_type> get_padded_bitrates(const bitrate_type& bitrate, std::size_t bitrate_seen) {
                        using namespace nil::crypto3::detail;

                        std::vector<bitrate_type> padded_bitrates;
                        bitrate_type new_bitrate = bitrate; // Start with the current bitrate

                        if ((bitrate_bits - bitrate_seen) >= 3) {
                            // add 0110 (first 01 is domain separatoin byte)
                            injector_type::inject(unbounded_shr(high_bits<word_bits>(~word_type(), 2), 1), 3, new_bitrate,
                                                  bitrate_seen);
                            // fill with 0...0
                            bitrate_type zeros;
                            std::fill(zeros.begin(), zeros.end(), 0);
                            injector_type::inject(zeros, bitrate_bits - 1 - bitrate_seen, new_bitrate, bitrate_seen);

                            // add the last 1
                            injector_type::inject(high_bits<word_bits>(~word_type(), 1), 1, new_bitrate,
                                                  bitrate_seen);

                            padded_bitrates.push_back(new_bitrate);
                        } else {
                            throw;
                            // If there's not enough space
                            std::size_t ind = bitrate_bits - bitrate_seen - 1;
                            new_bitrate[bitrate_words - 1] &= ~high_bits<word_bits>(~word_type(), ind + 1);
                            new_bitrate[bitrate_words - 1] |= high_bits<word_bits>(~word_type(), ind);

                            padded_bitrates.push_back(new_bitrate);

                            // Create an additional bitrate for the remaining padding
                            bitrate_type extra_bitrate;
                            std::fill(extra_bitrate.begin(), extra_bitrate.end(), 0);

                            // Padding logic for the extra bitrate
                            // pad 1 (since the bitrate is initially all zeros, just set the first bit to 1)
                            std::size_t injected_bits_n = 0;
                            injector_type::inject(high_bits<word_bits>(~word_type(), 1), 1, extra_bitrate, injected_bits_n);
                            BOOST_ASSERT(injected_bits_n == 1); // OR == word_bits?

                            padded_bitrates.push_back(extra_bitrate);
                        }

                        return padded_bitrates;
                    }
                };
            }    // namespace detail
        }    // namespace hashes
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_PADDING_HPP
