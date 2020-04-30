

#include "catch2/catch.hpp"
#include <metrics.h>

extern "C" {
    extern void tick_all();
}
TEST_CASE("test-metrics") {
    rate_t exp;
    rate_t cma;

    metrics_rate_init(&exp, EWMA_1m);
    metrics_rate_init(&cma, MMA_1m);

    metrics_rate_update(&exp, 1000);
    metrics_rate_update(&cma, 1000);

    for (int i=0; i<100; i++) {
        tick_all();
        printf("%d:\tewma=%.10lf\tmma=%lf\n", i, metrics_rate_get(&exp), metrics_rate_get(&cma));
    }
};