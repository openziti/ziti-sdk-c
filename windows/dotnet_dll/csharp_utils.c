#include <stdint.h>
#include <nf/ziti.h>
#include <stdlib.h>
#include <uv.h>

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)

uv_timer_t* registerUVTimerC(uv_loop_t* loop, uv_timer_cb timer_cb, uint64_t iterations, uint64_t delay) {
	
	uv_timer_t* uvt = calloc(1, sizeof(uv_timer_t));
	uv_timer_init(loop, uvt);
	uv_timer_start(uvt, timer_cb, iterations, delay);
	return uvt;
}
