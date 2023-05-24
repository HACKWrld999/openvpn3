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

// RAII classes for resource management

#pragma once

#include <openvpn/init/scoped_acq.hpp>
#include <openvpn/init/engineinit.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/compress/compress.hpp>


namespace openvpn {
namespace InitProcess {

// Because of the atexit handling of the teardown, if needed, OpenSSL_RAII should appear
// first in the ScopedAcqStack template parameter list.  It will be destroyed last.
struct OpenSSL_RAIIinit final : ScopedAcq
{
    OpenSSL_RAIIinit()
    {
#if defined(USE_OPENSSL) || (defined(USE_MINICRYPTO) && (defined(OPENVPN_ARCH_x86_64) || defined(OPENVPN_ARCH_i386)))
        init_openssl("auto");
#endif
    }

    ~OpenSSL_RAIIinit()
    {
        // no explicit destruction for the ENGINE_load_builtin_engines()
        // ENGINE_register_all_complete() and OpenSSLContext::SSL::init_static()
        // resources acquired via the init_openssl() above.  The OPENSSL_cleanup()
        // happens as a registered at_exit function
    }
};

struct OpenSSL_RAIIexplicit final : ScopedAcq
{
    OpenSSL_RAIIexplicit()
    {
#if defined(USE_OPENSSL)
        OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
#endif
    }

    ~OpenSSL_RAIIexplicit()
    {
#if defined(USE_OPENSSL)
        OPENSSL_cleanup();
#endif
    }
};

struct Base64_RAII final : ScopedAcq
{
    Base64_RAII()
    {
        base64_init_static();
    }

    ~Base64_RAII()
    {
        base64_uninit_static();
    }
};

// not sure why the next two should be RAII.  Looks like in both cases there's no need
// to recover anything
struct Time_RAII final : ScopedAcq
{
    Time_RAII()
    {
        Time::reset_base();
    }

    ~Time_RAII() = default; // do nothing
};

struct Compress_RAII final : ScopedAcq
{
    Compress_RAII()
    {
        CompressContext::init_static();
    }

    ~Compress_RAII() = default; // do nothing
};

} // namespace InitProcess
} // namespace openvpn
