//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2023 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Scoped Initialization and Cleanup

#pragma once

#include <type_traits>
#include <utility>
#include <memory>
#include <stack>


namespace openvpn {
namespace InitProcess {

// the base class of any class that wants to manage acquisition and release of a
// resource
struct ScopedAcq
{
    ScopedAcq() = default;

    virtual ~ScopedAcq() = default;

    // non-copyable and non-assignable
    ScopedAcq(const ScopedAcq &) = delete;
    ScopedAcq &operator=(const ScopedAcq &) = delete;
};

template <typename... Elements>
class ScopedAcqStack;

template <typename Tp>
struct sas_size;

// class sas_size; based on tuple_size
template <typename... Elements>
struct sas_size<ScopedAcqStack<Elements...>>
    : public std::integral_constant<std::size_t, sizeof...(Elements)>
{
};

// class sas_element; based on tuple_element
template <std::size_t I, typename Tp>
struct sas_element;

// recursion case
template <std::size_t I, typename Head, typename... Tail>
struct sas_element<I, ScopedAcqStack<Head, Tail...>>
    : sas_element<I - 1, ScopedAcqStack<Tail...>>
{
    constexpr sas_element() = default;
};

// recursion basis case
template <typename Head, typename... Tail>
struct sas_element<0, ScopedAcqStack<Head, Tail...>>
{
    typedef Head type;

    constexpr sas_element() = default;
};

// Error case for sas_element: invalid index
template <size_t I>
struct sas_element<I, ScopedAcqStack<>>
{
    static_assert(I < sas_size<ScopedAcqStack<>>::value,
                  "sas index out of range");
};

// Building the sas_stack with the stk_builder class
using sas_stack = std::stack<std::unique_ptr<ScopedAcq>>;

struct sas_stk
{
    sas_stack stack;
};

template <typename T, std::size_t... Is>
struct stk_builder;

// Recursive stk_builder case
template <typename T, std::size_t I, std::size_t... Is>
struct stk_builder<T, I, Is...> : public stk_builder<T, Is...>, virtual sas_stk
{
    stk_builder()
    {
        auto sacq = std::unique_ptr<ScopedAcq>(new typename sas_element<I, T>::type);
        stack.push(std::move(sacq));
    }
};

// Base stk_builder case
template <typename T, std::size_t I>
struct stk_builder<T, I> : virtual sas_stk
{
    stk_builder()
    {
        auto sacq = std::unique_ptr<ScopedAcq>(new typename sas_element<I, T>::type);
        stack.push(std::move(sacq));
    }
};

// rev_elts -- reverse the indices so I == 0 gets instantiated first
// Recursive rev_elts case
template <typename T, std::size_t I, std::size_t... Is>
struct rev_elts : rev_elts<T, I - 1, Is..., I - 1>
{
};

// Base rev_elts case; if ScopedAcqStack has 3 elements, index list, Is <2, 1, 0> is
// passed to stk_builder (vs tuple-like index generation which is 0, 1, 2); this causes
// the class at index 0 to be instantiated and pushed on the stack first
template <typename T, std::size_t... Is>
struct rev_elts<T, 0, Is...> : stk_builder<T, Is...>
{
};

template <typename... Elements>
class ScopedAcqStack
{
    using type = ScopedAcqStack<Elements...>;

    sas_stack stack_;

  public:
    explicit constexpr ScopedAcqStack()
    {
        // rev_elts reverses the elements because the tuple model we borrowed above
        // naturally would instantiate in right-to-left order (and that's ok, unless I'm
        // missing an easier solution?). The rev_elts is also derived from the
        // stk_builder class so its ctor creates the stack of runtime objects for which
        // we are looking.
        rev_elts<type, sizeof...(Elements)> rev;
        // move it into a member variable to delete in an orderly LIFO manner
        stack_ = std::move(rev.stack);
    }

    ~ScopedAcqStack()
    {
        while (!stack_.empty())
        {
            stack_.pop();
        }
    }
};

} // namespace InitProcess
} // namespace openvpn
