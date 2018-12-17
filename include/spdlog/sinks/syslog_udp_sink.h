//
// Copyright(c) 2015 Gabi Melman.
// Distributed under the MIT License (http://opensource.org/licenses/MIT)
//

#pragma once

#ifndef SPDLOG_H
#error "spdlog.h must be included before this file."
#endif

#include "spdlog/sinks/base_sink.h"

#include <array>
#include <string>
#include <sys/socket.h>
//#include <syslog.h>

namespace spdlog {
    namespace sinks {
        namespace syslog_udp {
            enum priority {
//                EMERG = 0,
//                ALERT = 1,
                        kCRIT = 2,
                kERR = 3,
                kWARNING = 4,
//                NOTICE = 5,
                        kINFO = 6,
                kDEBUG = 7,
            };
        }
/**
 * Sink that write to syslog using udp.
 *
 * Locking is not needed, as `sendmsg()` itself is thread-safe.
 */
        template<typename Mutex>
        class syslog_udp_sink : public base_sink<Mutex> {
        public:
            //
            explicit syslog_udp_sink(int fd, const struct sockaddr *sockServerAddr, socklen_t sockServerAddrLen,
                                     std::string host = "", std::string ident = "", int syslog_facility = (1 << 3))
                    : ident_(std::move(ident)),
                      host_(std::move(host)),
                      fd_(fd),
                      sockServerAddrLen_(std::min(sockServerAddrLen, (socklen_t) sizeof(sockServerAddr_))),
                      syslog_facility_(syslog_facility) {
                priorities_[static_cast<size_t>(level::trace)] = syslog_udp::priority::kDEBUG;
                priorities_[static_cast<size_t>(level::debug)] = syslog_udp::priority::kDEBUG;
                priorities_[static_cast<size_t>(level::info)] = syslog_udp::priority::kINFO;
                priorities_[static_cast<size_t>(level::warn)] = syslog_udp::priority::kWARNING;
                priorities_[static_cast<size_t>(level::err)] = syslog_udp::priority::kERR;
                priorities_[static_cast<size_t>(level::critical)] = syslog_udp::priority::kCRIT;
                priorities_[static_cast<size_t>(level::off)] = syslog_udp::priority::kINFO;

                memcpy(&sockServerAddr_, sockServerAddr, sockServerAddrLen_);
            }

            ~syslog_udp_sink() override {
                if (fd_ == -1) {
                    close(fd_);
                }
            }

            syslog_udp_sink(const syslog_udp_sink &) = delete;

            syslog_udp_sink &operator=(const syslog_udp_sink &) = delete;

        protected:
            void sink_it_(const details::log_msg &msg) override {
                int prio = syslog_prio_from_level(msg);
                int prival = syslog_facility_ + prio;

                auto msgstr = fmt::to_string(msg.payload);

                char tmpbuf[256];

                char datestr[50];
                time_t now = time(nullptr);
                struct tm a_tm = {};
                localtime_r(&now, &a_tm);
                size_t len = strftime(datestr, sizeof(datestr) - 1, "%Y-%m-%dT%T.00Z", &a_tm);
                datestr[len] = '\0';

                int buflen = snprintf(tmpbuf, sizeof(tmpbuf), "<%d>1 %s %s %s[%d] - - ",
                                      prival,
                                      datestr,
                                      (host_.empty()) ? "-" : host_.c_str(),
                                      (ident_.empty()) ? "-" : ident_.c_str(),
                                      getpid()
                );


                iovec a_iovec[2];
                a_iovec[0].iov_base = tmpbuf;
                a_iovec[0].iov_len = std::min((size_t) buflen, sizeof(tmpbuf) - 1);

                a_iovec[1].iov_base = (void *) msgstr.c_str();
                a_iovec[1].iov_len = msgstr.length();

                msghdr h;
                memset(&h, 0, sizeof(h));
                h.msg_iovlen = 2;
                h.msg_iov = a_iovec;
                h.msg_name = &sockServerAddr_;
                h.msg_namelen = sockServerAddrLen_;

                ssize_t res = sendmsg(fd_, &h, MSG_DONTWAIT);
            }

            void flush_() override {}

        private:
            std::array<int, 7> priorities_;
            // must store the ident because the man says openlog might use the pointer as
            // is and not a string copy
            const std::string ident_;

            const std::string host_;

            int fd_;
            socklen_t sockServerAddrLen_;
            struct sockaddr sockServerAddr_;

            int syslog_facility_;

            //
            // Simply maps spdlog's log level to syslog priority level.
            //
            int syslog_prio_from_level(const details::log_msg &msg) const {
                return priorities_[static_cast<size_t>(msg.level)];
            }
        };

        using syslog_udp_sink_mt = syslog_udp_sink<std::mutex>;
        using syslog_udp_sink_st = syslog_udp_sink<details::null_mutex>;
    } // namespace sinks

// Create and register a syslog logger
    template<typename Factory = default_factory>
    inline std::shared_ptr<logger> syslog_udp_logger_mt(
            const std::string &logger_name, const std::string &syslog_ident = "", int syslog_option = 0,
            int syslog_facility = (1 << 3)) {
        return Factory::template create<sinks::syslog_udp_sink_mt>(logger_name, syslog_ident, syslog_option,
                                                                   syslog_facility);
    }

    template<typename Factory = default_factory>
    inline std::shared_ptr<logger> syslog_udp_logger_st(
            const std::string &logger_name, const std::string &syslog_ident = "", int syslog_option = 0,
            int syslog_facility = (1 << 3)) {
        return Factory::template create<sinks::syslog_udp_sink_st>(logger_name, syslog_ident, syslog_option,
                                                                   syslog_facility);
    }
} // namespace spdlog
