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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <nf/ziti.h>
#include <zt_internal.h>
#include <uv.h>

/*stolen directly from Eugene for one place - probably not needed...*/
#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
return(code);\
}} while(0)

extern "C"
{
	typedef void (*uv_timer_cb)(uv_timer_t* handle);
	
	void on_nf_init(nf_context _nf, int status, void* ctx);


	void timerCallback(uv_timer_t* handle) {
		printf("timer calling back\n");
	}
	void timerCallback2(uv_timer_t* handle) {
		printf("timer calling back2\n");
	}

	void* registerUVTimerC(uv_loop_t* loop, uv_timer_cb timer_cb, uint64_t iterations, uint64_t delay);
	__declspec(dllexport)
	void* registerUVTimer(uv_loop_t* loop, uv_timer_cb timer_cb, uint64_t iterations, uint64_t delay) {
		return registerUVTimerC(loop, timer_cb, iterations, delay);
	}

	__declspec(dllexport)
	void unRegisterUVTimer(uv_loop_t* loop, uv_timer_t* timer) {
		
		uv_unref((uv_handle_t*)& timer);
	}

	__declspec(dllexport)
	int exported_NF_init(const char* config, uv_loop_t* loopIn, nf_init_cb cb, void* init_ctx)
	{
		char* config_path_copy = strdup(config); //in case the managed memory is collected - duplicate the config
		DIE(NF_init(config_path_copy, loopIn, cb, init_ctx));
		
		// loop will finish after the request is complete and NF_shutdown is called
		uv_run(loopIn, UV_RUN_DEFAULT);
		free(config_path_copy); //free the duplicated config path
		printf("========================\n");

		return EXIT_SUCCESS;
	}

	__declspec(dllexport)
	int exported_NF_conn_init(nf_context nf_ctx, nf_connection* conn, void* data) {
		return NF_conn_init(nf_ctx, conn, data);
	}
	
	__declspec(dllexport)
	int exported_NF_shutdown(nf_context conn) {
		return NF_shutdown(conn);
	}

	__declspec(dllexport)
	void exported_NF_dump(nf_context ctx) {
		return NF_dump(ctx);
	}

	__declspec(dllexport)
	int exported_NF_service_available(nf_context ctx, const char* service) {
		return NF_service_available(ctx, service);
	}

	__declspec(dllexport)
	int exported_NF_free(nf_context nf_context) {
		return NF_free(&nf_context);
	}

	__declspec(dllexport)
	int exported_NF_dial(nf_connection conn, const char* service, nf_conn_cb conn_cb, nf_data_cb data_cb) {
		return NF_dial(conn, service, conn_cb, data_cb);
	}
	
	__declspec(dllexport)
	int exported_NF_dial_with_context(nf_connection conn, const char* service, nf_conn_cb conn_cb, nf_data_cb data_cb, void* context) {
		return NF_dial(conn, service, conn_cb, data_cb);
	}

	__declspec(dllexport)
	int exported_NF_write(nf_connection conn, uint8_t* data, size_t length, nf_write_cb write_cb, void* context) {
		return NF_write(conn, data, length, write_cb, context);
	}

	__declspec(dllexport)
	int exported_NF_close(nf_connection conn) {
		return NF_close(&conn);
	}

	__declspec(dllexport)
	void* exported_NF_conn_data(nf_connection conn) {
		return NF_conn_data(conn);
	}

	__declspec(dllexport)
	void exported_shutdown(nf_connection conn) {
		NF_shutdown(conn->nf_ctx);
	}

	__declspec(dllexport)
	void exported_NF_freeByConnection(nf_connection conn) {
		NF_free(&conn->nf_ctx);
	}

	__declspec(dllexport)
	void* createUvLoop() {
		return uv_default_loop(); //for now
	}

    __declspec(dllexport)
    int exported_NF_set_timeout(nf_context ctx, int timeout) {
        return NF_set_timeout(ctx, timeout);
    }
    
}