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

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/endian_shift.hpp>
#include <nil/crypto3/detail/inject.hpp>

#include <nil/crypto3/hash/accumulators/bits_count.hpp>

#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>
#include <nil/crypto3/hash/accumulators/parameters/iterator_last.hpp>

#include <nil/crypto3/hash/type_traits.hpp>

#include <boost/accumulators/statistics/count.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename Params, typename BasePointGeneratorHash, typename Group>
            struct pedersen;
        }
        namespace accumulators {
            namespace impl {
                template<typename Hash, typename = void>
                struct hash_impl : boost::accumulators::accumulator_base {
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
                    constexpr static const std::size_t length_words = length_bits / word_bits;
                    BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);

                    typedef ::nil::crypto3::detail::injector<endian_type, word_bits, block_words, block_bits>
                        injector_type;

                public:
                    typedef typename hash_type::digest_type result_type;

                    // The constructor takes an argument pack.
                    hash_impl(boost::accumulators::dont_care) : filled(false), total_seen(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
std::cout << "hash/accumulators/hash.hpp : 103 total_seen = " << total_seen << "\n";
                        construction_type res = construction;
                        return res.digest(cache, total_seen % block_bits);
                    }

                protected:
                    inline void resolve_type(const block_type &value, std::size_t bits) {
                        // total_seen += bits == 0 ? block_bits : bits;
                        process(value, bits == 0 ? block_bits : bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        // total_seen += bits == 0 ? word_bits : bits;
                        process(value, bits == 0 ? word_bits : bits);
                    }

                    inline void process(const block_type &value, std::size_t value_seen) {
// Uncommenting this cout leads to fix.
// std::cout << "hash/accumulators/hash.hpp : process total_seen = " << total_seen << "\n";
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            construction.process_block(cache, block_bits);
                            filled = false;
                        }

                        std::size_t cached_bits = total_seen % block_bits;
// Uncommenting this cout leads to fix.
//std::cout << "hash/accumulators/hash.hpp process " << "value_seen = " << value_seen << 
//    "total_seen = " << total_seen << " block_words = " << block_words << " block_bits = " << block_bits << "cached_bits = " << cached_bits << "\n";

                        if (cached_bits != 0) {
                            // If there are already any bits in the cache

                            std::size_t needed_to_fill_bits = block_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == block_bits) {
                                // If there are enough bits in the incoming value to fill the block
                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    construction.process_block(cache, block_bits);
                                    filled = false;

                                    // If there are some remaining bits in the incoming value - put them into the cache,
                                    // which is now empty

                                    cached_bits = 0;

                                    injector_type::inject(
                                        value, value_seen - new_bits_to_append, cache, cached_bits, new_bits_to_append);
                                    total_seen += value_seen - new_bits_to_append;
                                }
                            }
                        } else {

                            total_seen += value_seen;

                            // If there are no bits in the cache
                            if (value_seen == block_bits) {
                                // The incoming value is a full block
                                filled = true;

                                std::copy(value.begin(), value.end(), cache.begin());
                            } else {
                                if (word_bits == 40) {
//std::cout << "Moving value of size " << value_seen << " into a block of size " << block_bits << " word_bits = " << word_bits << std::endl;
                                }

                                // The incoming value is not a full block
                                if (value_seen > block_bits)
                                    std::cout << "value_seen > block_bits\n";
                                std::copy(value.begin(),
                                          value.begin() + value_seen / word_bits + (value_seen % word_bits ? 1 : 0),
                                          cache.begin());
                            }
                        }
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            construction.process_block(cache, block_bits);
                            filled = false;
                        }

                        std::size_t cached_bits = total_seen % block_bits;

                        if (cached_bits % word_bits != 0) {
                            std::size_t needed_to_fill_bits = block_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == block_bits) {
                                // If there are enough bits in the incoming value to fill the block

                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    construction.process_block(cache, block_bits);
                                    filled = false;

                                    // If there are some remaining bits in the incoming value - put them into the cache,
                                    // which is now empty
                                    cached_bits = 0;

                                    injector_type::inject(
                                        value, value_seen - new_bits_to_append, cache, cached_bits, new_bits_to_append);

                                    total_seen += value_seen - new_bits_to_append;
                                }
                            }

                        } else {
                            cache[cached_bits / word_bits] = value;

                            total_seen += value_seen;
                        }
                    }

                    bool filled;
                    std::size_t total_seen;
                    block_type cache;
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
