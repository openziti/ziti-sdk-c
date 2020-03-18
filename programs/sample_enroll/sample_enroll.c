/*
Copyright 2019-2020 NetFoundry, Inc.

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

#include <nf/ziti.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <uv.h>

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", ziti_errorstr(code));\
exit(code);\
}} while(0)

const char *output_file;

static int write_identity_file( char *data )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = strlen(data);

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( data, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( ZITI_OK );
}

void on_nf_enroll(uint8_t *data, int length, int status) {
    DIE(status);

    int rc = write_identity_file( (char*) data );

    DIE(rc);
}

int main(int argc, char** argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);
#endif
    uv_loop_t *loop = uv_default_loop();

    output_file = argv[2];

    DIE(NF_enroll(argv[1], loop, on_nf_enroll));

    // loop will finish after the request is complete and NF_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("\nSuccess\n");

}