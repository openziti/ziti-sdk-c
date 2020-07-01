/*
Copyright (c) 2020 Netfoundry, Inc.

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

#include <uv.h>
#include <stdlib.h>
#include <string.h>


static void alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void in_read_cb(uv_stream_t *h, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        if (nread != UV_EOF)
            fprintf(stderr, "unexpected input error: %zd(%s)", nread, uv_strerror(nread));
        uv_loop_close(h->loop);
    } else {
        buf->base[nread] = '\0';
        char *rest;
        char *cmd = strtok_r(buf->base, " ", &rest);

        if (strcmp(cmd, "load") == 0) {

        }
    }
    free(buf->base);
}

int main(int argc, char *argv[]) {
    uv_loop_t *l = uv_default_loop();

    uv_pipe_t in;
    uv_pipe_init(l, &in, 0);
    uv_pipe_open(&in, 0);
    uv_read_start((uv_stream_t *) &in, alloc_cb, in_read_cb);

    uv_run(l, UV_RUN_DEFAULT);

    return 0;
}