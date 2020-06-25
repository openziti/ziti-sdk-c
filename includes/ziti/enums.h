#ifndef ZITI_ENUM_H
#define ZITI_ENUM_H
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EWMA_1m,
    EWMA_5m,
    EWMA_15m,
    MMA_1m,
    CMA_1m,
    EWMA_5s,
} rate_type;

#ifdef __cplusplus
}
#endif
#endif /* ZITI_ENUM_H */
