/* schema.h - a pragmatic JSON Schema (subset) validator over ntc_json.
 *
 * Supported keywords: type (object/array/string/number/integer/boolean/null),
 * required, properties, additionalProperties (bool), items, enum, minimum,
 * maximum, minLength, maxLength, minItems, maxItems. Enough to make request
 * bodies self-checking and the auto-OpenAPI typed; documented subset, not the
 * full spec. */
#ifndef NTC_SCHEMA_H
#define NTC_SCHEMA_H

#include <stdbool.h>
#include <stddef.h>

#include "ntc/json.h"

/* Validate `instance` against `schema` (both already parsed). On failure returns
 * false and writes a short reason into err (if provided). */
bool ntc_schema_validate(const ntc_json *schema, const ntc_json *instance,
                         char *err, size_t errcap);

#endif /* NTC_SCHEMA_H */
