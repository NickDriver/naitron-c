/* signal.h - process-level crash nets.
 *
 * Ignores SIGPIPE (writing to a closed socket must not kill the server) and
 * installs a fail-loud crash handler that dumps a backtrace before dying, so
 * the supervisor can restart a diagnosable process. */
#ifndef NTC_SIGNAL_H
#define NTC_SIGNAL_H

void ntc_install_signal_handlers(void);

#endif /* NTC_SIGNAL_H */
