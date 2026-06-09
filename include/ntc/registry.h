/* registry.h - the control-plane registry (SQLite-backed).
 *
 * A *utility* DB (ntc.db), not the app's data store: it holds the dynamic
 * services + routes the orchestrator spawns and the gateway routes to. Only the
 * core writes it; the CLI/MCP (P6/P7) mutate it through the core. */
#ifndef NTC_REGISTRY_H
#define NTC_REGISTRY_H

#include <stddef.h>
#include <stdbool.h>
#include "ntc/err.h"

typedef struct ntc_registry ntc_registry;

typedef struct { char name[64]; char bin[256]; int enabled; } ntc_service_row;
typedef struct { char method[8]; char pattern[128]; char service[64]; } ntc_route_row;

NTC_NODISCARD ntc_err ntc_registry_open(ntc_registry **out, const char *path);
void ntc_registry_close(ntc_registry *r);

NTC_NODISCARD ntc_err ntc_registry_add_service(ntc_registry *r, const char *name,
                                               const char *bin);
NTC_NODISCARD ntc_err ntc_registry_remove_service(ntc_registry *r, const char *name);
NTC_NODISCARD ntc_err ntc_registry_add_route(ntc_registry *r, const char *method,
                                             const char *pattern, const char *service);

NTC_NODISCARD ntc_err ntc_registry_list_services(ntc_registry *r,
        ntc_service_row *out, size_t max, size_t *count);
NTC_NODISCARD ntc_err ntc_registry_list_routes(ntc_registry *r,
        ntc_route_row *out, size_t max, size_t *count);

/* key/value config (e.g. the control-plane token). */
NTC_NODISCARD ntc_err ntc_registry_get_config(ntc_registry *r, const char *key,
        char *out, size_t cap, bool *found);
NTC_NODISCARD ntc_err ntc_registry_set_config(ntc_registry *r, const char *key,
        const char *value);

#endif /* NTC_REGISTRY_H */
