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

#include "test_common.h"

#include <openvpn/init/scoped_acq.hpp>

#include <queue>

using namespace openvpn::InitProcess;

class RAII_checker
{
    static std::queue<std::string> Q;

  public:
    void log_msg(const std::string &str)
    {
        push_message(std::move(str));
    }

    static void push_message(const std::string &&str)
    {
        Q.push(std::move(str));
    }

    static std::string get_messages()
    {
        std::ostringstream oss;
        std::string delim;

        while (!Q.empty())
        {
            oss << delim << Q.front();
            Q.pop();
            delim = " | ";
        }
        return oss.str();
    }
};

std::queue<std::string> RAII_checker::Q;

struct Res1_RAII : public ScopedAcq, public RAII_checker
{
    Res1_RAII()
    {
        log_msg("Res1_RAII ctor");
    }
    virtual ~Res1_RAII()
    {
        log_msg("Res1_RAII dtor");
    }
};

struct Res2_RAII : public ScopedAcq, public RAII_checker
{
    Res2_RAII()
    {
        log_msg("Res2_RAII ctor");
    }
    virtual ~Res2_RAII()
    {
        log_msg("Res2_RAII dtor");
    }
};

struct Res3_RAII : public ScopedAcq, public RAII_checker
{
    Res3_RAII()
    {
        log_msg("Res3_RAII ctor");
    }
    virtual ~Res3_RAII()
    {
        log_msg("Res3_RAII dtor");
    }
};


std::string misc_scoped_acq_result = "Res1_RAII ctor | Res2_RAII ctor | Res3_RAII ctor"
                                     " | inside the scope | "
                                     "Res3_RAII dtor | Res2_RAII dtor | Res1_RAII dtor";

TEST(misc, scoped_acq)
{
    {
        ScopedAcqStack<Res1_RAII, Res2_RAII, Res3_RAII> sas;
        std::string inside_msg("inside the scope");
        RAII_checker::push_message(std::move(inside_msg));
    }
    EXPECT_EQ(RAII_checker::get_messages(), misc_scoped_acq_result);
}
