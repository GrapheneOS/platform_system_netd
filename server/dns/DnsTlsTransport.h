/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _DNS_DNSTLSTRANSPORT_H
#define _DNS_DNSTLSTRANSPORT_H

#include "dns/DnsTlsSessionCache.h"
#include "dns/DnsTlsServer.h"

#include <netdutils/Slice.h>

namespace android {
namespace net {

class IDnsTlsSocketFactory;

class DnsTlsTransport {
public:
    DnsTlsTransport(const DnsTlsServer& server, unsigned mark,
                    IDnsTlsSocketFactory* _Nonnull factory) :
            mMark(mark), mServer(server), mFactory(factory) {}
    ~DnsTlsTransport();

    typedef DnsTlsServer::Response Response;
    typedef DnsTlsServer::Result Result;

    // Given a |query|, this method sends it to the server
    // and returns the server's response synchronously.
    Result query(const netdutils::Slice query);

    // Check that a given TLS server is fully working on the specified netid, and has the
    // provided SHA-256 fingerprint (if nonempty).  This function is used in ResolverController
    // to ensure that we don't enable DNS over TLS on networks where it doesn't actually work.
    static bool validate(const DnsTlsServer& server, unsigned netid);

private:
    DnsTlsSessionCache mCache;

    const unsigned mMark;  // Socket mark
    const DnsTlsServer mServer;
    IDnsTlsSocketFactory* _Nonnull const mFactory;
};

}  // end of namespace net
}  // end of namespace android

#endif  // _DNS_DNSTLSTRANSPORT_H
