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


#include <openvpn/log/logbase.hpp>

#include <openvpn/init/scoped_raii.hpp>

#include <gtest/gtest.h>

#include <utility>

using namespace openvpn::InitProcess;

int main(int argc, char **argv)
{
    ScopedAcqStack<OpenSSL_RAIIinit, Base64_RAII> sas;

    ::testing::InitGoogleTest(&argc, argv);
    auto ret = RUN_ALL_TESTS();

    return ret;
}
