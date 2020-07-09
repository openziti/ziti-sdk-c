#ifndef ZITI_ENUM_H
#define ZITI_ENUM_H
#ifdef __cplusplus
extern "C" {
#endif


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

#ifdef __cplusplus
}
#endif
#endif /* ZITI_ENUM_H */
