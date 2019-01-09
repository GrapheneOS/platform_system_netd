/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef _DNSPROXYLISTENER_H__
#define _DNSPROXYLISTENER_H__

#include <binder/IServiceManager.h>
#include <sysutils/FrameworkListener.h>

#include "EventReporter.h"
#include "NetdCommand.h"
#include "netd_resolv/resolv.h"  // android_net_context

namespace android {
namespace net {

class NetworkController;

class DnsProxyListener : public FrameworkListener {
  public:
    explicit DnsProxyListener(const NetworkController* netCtrl, EventReporter* eventReporter);
    virtual ~DnsProxyListener() {}

    static constexpr const char* SOCKET_NAME = "dnsproxyd";

  private:
    const NetworkController *mNetCtrl;
    EventReporter *mEventReporter;

    class GetAddrInfoCmd : public NetdCommand {
      public:
        explicit GetAddrInfoCmd(DnsProxyListener* dnsProxyListener);
        virtual ~GetAddrInfoCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);

      private:
        DnsProxyListener* mDnsProxyListener;
    };

    /* ------ getaddrinfo ------*/
    class GetAddrInfoHandler {
      public:
        // Note: All of host, service, and hints may be NULL
        GetAddrInfoHandler(SocketClient* c, char* host, char* service, addrinfo* hints,
                           const android_net_context& netcontext, int reportingLevel);
        ~GetAddrInfoHandler();

        void run();

      private:
        void doDns64Synthesis(int32_t* rv, addrinfo** res);

        SocketClient* mClient;  // ref counted
        char* mHost;            // owned. TODO: convert to std::string.
        char* mService;         // owned. TODO: convert to std::string.
        addrinfo* mHints;       // owned
        android_net_context mNetContext;
        const int mReportingLevel;
    };

    /* ------ gethostbyname ------*/
    class GetHostByNameCmd : public NetdCommand {
      public:
        explicit GetHostByNameCmd(DnsProxyListener* dnsProxyListener);
        virtual ~GetHostByNameCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);

      private:
        DnsProxyListener* mDnsProxyListener;
    };

    class GetHostByNameHandler {
      public:
        GetHostByNameHandler(SocketClient* c, char* name, int af,
                             const android_net_context& netcontext, int reportingLevel);
        ~GetHostByNameHandler();

        void run();

      private:
        void doDns64Synthesis(int32_t* rv, hostent** hpp);

        SocketClient* mClient; //ref counted
        char* mName;           // owned. TODO: convert to std::string.
        int mAf;
        android_net_context mNetContext;
        const int mReportingLevel;
    };

    /* ------ gethostbyaddr ------*/
    class GetHostByAddrCmd : public NetdCommand {
      public:
        explicit GetHostByAddrCmd(const DnsProxyListener* dnsProxyListener);
        virtual ~GetHostByAddrCmd() {}
        int runCommand(SocketClient *c, int argc, char** argv);

      private:
        const DnsProxyListener* mDnsProxyListener;
    };

    class GetHostByAddrHandler {
      public:
        GetHostByAddrHandler(SocketClient *c,
                            void* address,
                            int addressLen,
                            int addressFamily,
                            const android_net_context& netcontext);
        ~GetHostByAddrHandler();

        void run();

      private:
        void doDns64ReverseLookup(hostent** hpp);

        SocketClient* mClient;  // ref counted
        void* mAddress;    // address to lookup; owned
        int mAddressLen; // length of address to look up
        int mAddressFamily;  // address family
        android_net_context mNetContext;
    };

    /* ------ resnsend ------*/
    class ResNSendCommand : public NetdCommand {
      public:
        explicit ResNSendCommand(DnsProxyListener* dnsProxyListener);
        ~ResNSendCommand() override {}
        int runCommand(SocketClient* c, int argc, char** argv);

      private:
        DnsProxyListener* mDnsProxyListener;
    };

    class ResNSendHandler {
      public:
        ResNSendHandler(SocketClient* c, std::string msg, const android_net_context& netcontext,
                        int reportingLevel);
        ~ResNSendHandler();

        void run();

      private:
        SocketClient* mClient;  // ref counted
        std::string mMsg;
        android_net_context mNetContext;
        const int mReportingLevel;
    };
};

}  // namespace net
}  // namespace android

#endif
