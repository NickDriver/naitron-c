/* Integration tests for the gateway (black-box, span processes).
 *
 * These are planned (TODO) for P4, when the out-of-process controller path and
 * a spawn-a-server harness exist. They register as integration tests so the
 * runner can list/select them now, and we'll flip TODO -> real as we build. */
#include "ntc/test.h"

ITEST_TODO(gateway, answers_200_over_tcp) {
    /* P4: spawn `ntc start`, connect, send a request, assert HTTP/1.1 200. */
}

ITEST_TODO(gateway, forwards_request_to_controller) {
    /* P4: register a controller, hit its route, assert the controller ran. */
}

ITEST_TODO(gateway, restarts_crashed_controller) {
    /* P5: kill a controller mid-flight, assert the supervisor restarts it. */
}
