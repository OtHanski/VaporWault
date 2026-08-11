/*
 * vapourwault-web-gateway — entry point.
 *
 * TASK-128 scope: prove the target links and runs cleanly on all CI
 * platforms. Real request handling (vw_gateway_session/vw_gateway_api) lands
 * in TASK-131-135; this stub only proves vw_core + vw_client_core link.
 */

#include "../core/vw_proto.h"
#include <stdio.h>

int main(void) {
    printf("vapourwault-web-gateway (protocol v%u)\n",
           (unsigned)VW_PROTO_VERSION_CURRENT);
    return 0;
}
