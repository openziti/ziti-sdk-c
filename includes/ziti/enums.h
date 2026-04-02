#ifndef ZITI_ENUM_H
#define ZITI_ENUM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const struct ziti_terminator_precedence_s {
    const uint8_t DEFAULT;
    const uint8_t REQUIRED;
    const uint8_t FAILED;
} PRECEDENCE;
/**
* @brief Represents the type and rate of metric to capture
* 
* Each enum contains the rate type and the expected duration metrics will be gathered
*
* CMA  - continually moving average
* EWMA - exponentially weighted moving average
* MMA  - modified moving average
*/
typedef enum {
    EWMA_1m,
    EWMA_5m,
    EWMA_15m,
    MMA_1m,
    CMA_1m,
    EWMA_5s,
    INSTANT,
} rate_type;

typedef enum {
    ziti_enroll_none = 0,
    ziti_enroll_cert,
    ziti_enroll_token,
} ziti_enroll_mode;

#ifdef __cplusplus
}
#endif
#endif /* ZITI_ENUM_H */
