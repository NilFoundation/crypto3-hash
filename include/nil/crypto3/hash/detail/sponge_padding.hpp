//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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
//---------------------------------------------------------------------------////

#ifndef CRYPTO3_SPONGE_PADDING_HPP
#define CRYPTO3_SPONGE_PADDING_HPP

#include <type_traits>
#include <vector>

#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/octet.hpp>


namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                template<typename Derived, typename Hash>
                class sponge_padding_base {
                public:
                    static std::vector<BlockType> get_padded_blocks(const BlockType& block, const std::size_t block_seen) {
                        static_assert(std::is_same<decltype(Derived::get_padded_blocks(block, block_seen)),
                                                std::vector<BlockType>>::value,
                                    "Derived class must implement static get_padded_blocks method");

                        return Derived::get_padded_blocks(block, block_seen);
                    }
                };
            }    // namespace detail
        }    // namespace hashes
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MERKLE_DAMGARD_PADDING_HPP
