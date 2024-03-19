//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_HASH_HPP
#define CRYPTO3_ACCUMULATORS_HASH_HPP

#include <concepts>


#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>
#include <boost/accumulators/statistics/count.hpp>
#include <boost/container/static_vector.hpp>
#include <boost/parameter/value_type.hpp>

#include <nil/crypto3/detail/block_cache.hpp>
#include <nil/crypto3/detail/endian_shift.hpp>
#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

#include <nil/crypto3/hash/accumulators/bits_count.hpp>

#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>
#include <nil/crypto3/hash/accumulators/parameters/iterator_last.hpp>

#include <nil/crypto3/hash/type_traits.hpp>


namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct pedersen;
        }
template<typename TIter>
void print_hex_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end, bool endl = true) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << "0x" << std::setfill('0') << std::setw(16) << std::right << *it << " ";
    }
    os << std::dec;
    if (endl) {
        os << std::endl;
    }
}
        namespace accumulators {
            namespace impl {
                template<typename Hash, typename = void>
                class hash_impl : public boost::accumulators::accumulator_base {
                protected:
                    typedef Hash hash_type;
                    typedef typename hash_type::construction::type construction_type;
                    typedef typename hash_type::construction::params_type params_type;

                    typedef typename params_type::digest_endian endian_type;

                    constexpr static const std::size_t word_bits = construction_type::word_bits;
                    typedef typename construction_type::word_type word_type;

                    constexpr static const std::size_t block_bits = construction_type::block_bits;
                    constexpr static const std::size_t block_words = construction_type::block_words;
                    typedef typename construction_type::block_type block_type;

                    constexpr static const std::size_t length_bits = params_type::length_bits;
                    // FIXME: do something more intelligent than capping at 64
                    constexpr static const std::size_t length_type_bits = length_bits < word_bits ? word_bits :
                                                                          length_bits > 64        ? 64 :
                                                                                                    length_bits;
                    typedef typename boost::uint_t<length_type_bits>::least length_type;
                    constexpr static const std::size_t length_words = length_bits / word_bits; // what is it and why do we need it?
                    BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);

                public:
                    typedef typename hash_type::digest_type result_type;

                    // The constructor takes an argument pack.
                    hash_impl(boost::accumulators::dont_care) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        construction_type res = construction; // Make a copy, so we can append more to existing state afterwards
                        const block_type block = cache_.get_block();
                        block_type b_packed;
                        nil::crypto3::detail::pack_to<endian_type, word_bits, word_bits>(block.begin(), block.end(), b_packed.begin());
                        std::cout << "cache inside result: " << std::endl;
                        print_hex_byteblob(std::cout, b_packed.begin(), b_packed.end());
                        if constexpr (nil::crypto3::hashes::is_sponge<hash_type>::value) {
                            // Sponge hash behavior
                            res.absorb_with_padding(b_packed, cache_.bits_used());
                            return res.digest();
                        } else {
                            // Non-sponge hash behavior
                            return res.digest(block, total_seen_);
                        }
                    }

                protected:
                    inline void resolve_type(const block_type &value, std::size_t bits) {
                        process(value, bits == 0 ? block_bits : bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        process(value, bits == 0 ? word_bits : bits);
                    }

                    inline void process(const block_type &value, std::size_t value_seen) {
                        std::size_t processed_bits = 0;

                        while (processed_bits < value_seen) {
                            std::size_t unused_bits_in_cache = cache_.capacity() - cache_.bits_used();
                            std::size_t remaining_bits = value_seen - processed_bits;
                            std::size_t bits_to_append = std::min(unused_bits_in_cache, remaining_bits);

                            cache_.append(value, bits_to_append, processed_bits);
                            processed_bits += bits_to_append;

                            if (cache_.is_full()) {
                                flush_cache_to_construction();
                            }
                        }

                        total_seen_ += value_seen;
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {
                        std::size_t processed_bits = 0;

                        // Directly append if cache is word aligned and has enough capacity
                        if (cache_.is_word_alligned() && cache_.capacity() - cache_.bits_used() >= value_seen) {
                            cache_.append(value, value_seen);
                            processed_bits = value_seen;
                        }

                        // Handle the case where the cache is not word-aligned or didn't have enough capacity in the aligned case
                        while (processed_bits < value_seen) {
                            std::size_t unused_bits_in_cache = cache_.capacity() - cache_.bits_used();
                            std::size_t remaining_bits = value_seen - processed_bits;
                            std::size_t bits_to_append = std::min(unused_bits_in_cache, remaining_bits);

                            cache_.append(value, bits_to_append, processed_bits);
                            processed_bits += bits_to_append;

                            if (cache_.is_full()) {
                                flush_cache_to_construction();
                            }
                        }

                        total_seen_ += value_seen;
                    }

                private:
                    void flush_cache_to_construction() {
                        std::cout << "cache for construction: " << std::endl;
                        print_hex_byteblob(std::cout, cache_.get_block().begin(), cache_.get_block().end());
                        if constexpr (nil::crypto3::hashes::is_sponge<hash_type>::value) {
                            construction.absorb(std::move(cache_.get_block()));
                        } else {
                            construction.process_block(std::move(cache_.get_block()));
                        }
                        cache_.clean();
                    }

                    std::size_t total_seen_ = 0;
                    nil::crypto3::detail::block_cache<block_type, block_bits, word_type, word_bits, endian_type> cache_;
                    construction_type construction;
                };

                template<typename Hash>
                struct hash_impl<Hash,
                                 typename std::enable_if<nil::crypto3::hashes::is_find_group_hash<Hash>::value ||
                                                         nil::crypto3::hashes::is_pedersen<Hash>::value ||
                                                         nil::crypto3::hashes::is_h2f<Hash>::value ||
                                                         nil::crypto3::hashes::is_h2c<Hash>::value>::type>
                    : boost::accumulators::accumulator_base {
                protected:
                    typedef Hash hash_type;
                    typedef typename hash_type::internal_accumulator_type internal_accumulator_type;

                public:
                    typedef typename hash_type::result_type result_type;

                    template<typename Args>
                    hash_impl(const Args &args) {
                        hash_type::init_accumulator(acc);
                    }

                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::iterator_last | nullptr]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return hash_type::process(acc);
                    }

                protected:
                    template<typename InputRange, typename InputIterator>
                    inline void resolve_type(const InputRange &range, InputIterator) {
                        hash_type::update(acc, range);
                    }

                    template<typename InputIterator>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        hash_type::update(acc, first, last);
                    }

                    mutable internal_accumulator_type acc;
                };
            }    // namespace impl

            namespace tag {
                template<typename Hash>
                struct hash : boost::accumulators::depends_on<bits_count> {
                    typedef Hash hash_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::hash_impl<Hash>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Hash, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::hash<Hash>>::type::result_type
                    hash(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::hash<Hash>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_HASH_HPP
