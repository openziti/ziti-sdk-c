/*
Copyright 2019 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
