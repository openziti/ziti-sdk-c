Ziti SDK for C
--------------
# Release 0.17.0

* Adds models for `intercept.v1` and `host.v1` service configuration types.
* Renames `ziti_intercept` model to `ziti_client_cfg_v1`.

# Release 0.14.0

* Adds `router_keepalive` option. It sets TCP keepalive on connections to edge routers.
* [uv-mbed](https://github.com/netfoundry/uv-mbed) is upgraded to [v0.5.1](https://github.com/netfoundry/uv-mbed/releases/tag/v0.5.1)
  * [libuv](https://github.com/libuv/libuv) upgraded to v1.38.0
  * adds websocket client: can be used with `ziti_src_t` to connect websockets over Ziti connections