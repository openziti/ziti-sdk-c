see: https://github.com/json-c/json-c/pull/915
this overlay is needed until json-c the above is resolved and released


This overlay disables using `duplocale` when building for apple operating systems. The json-c support for duplocale
causes numerous leaks, e.g.:

```
leaks Report Version: 4.0, multi-line stacks
Process 80752: 9841 nodes malloced for 960 KB
Process 80752: 32 leaks for 43216 total leaked bytes.

STACK OF 18 INSTANCES OF 'ROOT LEAK: <malloc in _duplocale>':
26  dyld                                  0x190bc9d54 start + 7184
25  ziti-edge-tunnel                      0x104582770 main + 164  ziti-edge-tunnel.c:2877
24  ziti-edge-tunnel                      0x104582060 commandline_run + 532  commandline.h:119
23  ziti-edge-tunnel                      0x104581fa0 commandline_run + 340  commandline.h:96
22  ziti-edge-tunnel                      0x104583f50 run + 1404  ziti-edge-tunnel.c:1548
21  ziti-edge-tunnel                      0x1045841ec run_tunnel + 556  ziti-edge-tunnel.c:909
20  ziti-edge-tunnel                      0x104584560 run_tunneler_loop + 604  ziti-edge-tunnel.c:1090
19  ziti-edge-tunnel                      0x104a73610 uv_run + 368  core.c:464
18  ziti-edge-tunnel                      0x104a91d18 uv__io_poll + 3200  kqueue.c:423
17  ziti-edge-tunnel                      0x104a80b28 uv__poll_io + 336  poll.c:64
16  ziti-edge-tunnel                      0x104611010 on_clt_io + 668  tlsuv.c:507
15  ziti-edge-tunnel                      0x10461174c process_inbound + 952  tlsuv.c:443
14  ziti-edge-tunnel                      0x10461d64c tr_read_cb + 64  http.c:95
13  ziti-edge-tunnel                      0x10461ca30 clt_read_cb + 572  http.c:123
12  ziti-edge-tunnel                      0x10461dc34 http_req_process + 160  http_req.c:92
11  ziti-edge-tunnel                      0x104aab428 llhttp_execute + 48  api.c:141
10  ziti-edge-tunnel                      0x104a9cdcc llhttp__internal_execute + 104  llhttp.c:10149
9   ziti-edge-tunnel                      0x104aa6bb0 llhttp__internal__run + 40252  llhttp.c:7524
8   ziti-edge-tunnel                      0x104aad768 llhttp__on_body + 108  api.c:444
7   ziti-edge-tunnel                      0x10461efe8 http_body_cb + 72  http_req.c:416
6   ziti-edge-tunnel                      0x1046210f4 um_inflate + 256  compression.c:125
5   ziti-edge-tunnel                      0x10461f1e8 inflator_cb + 92  http_req.c:340
4   ziti-edge-tunnel                      0x1045ab178 ctrl_body_cb + 308  ziti_ctrl.c:437
3   ziti-edge-tunnel                      0x104ae46a8 json_tokener_parse_ex + 188  json_tokener.c:343
2   libsystem_c.dylib                     0x190e4c580 _duplocale + 48
1   libsystem_malloc.dylib                0x190da57d8 _malloc + 88
0   libsystem_malloc.dylib                0x190dbdfb8 _malloc_zone_malloc_instrumented_or_legacy + 268 
```