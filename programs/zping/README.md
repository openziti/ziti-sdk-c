# Intro:  

What is zping?  zping replaces the function of icmp ping tool in a ziti network.

It provides an end to end latency measurment between any two ziti identities in a ziti network and like icmp ping will provide the following metrics upon completion of the ping session:

min, max and mean latency and standard deviation as well as % loss.

zping uses the addressable terminator function of ziti to direct ping requests to specific identities.

# Get the code :

Compile from source:

Linux:

   Create a dir
```
   mkdir zitiapps
```
```
   $ cd zitiapps
```   
```   
   $ git clone <repository url>
```
```
   $ cd ziti-sdk-c
```
```
   $ follow insructions for building in building.md
```
```
   $ cd build\programs\zping
```

# Setup the Network and the Ziti Service :

![Diagram](network.png)

1. Create or use an existing ziti network with at least one edge router.

2. Create at least two ziti identities and give them a common identity role i.e. #ping 

      e.g. zitiendpoint1, zitiendpoint2

3. Create a simple sdk service named “csdk01”.

4. Create a bind policy with identityRoles set to [#ping] and serviceroles set to [@ziti-ping].

5. Create a dial service policy with identityRoles set to [#ping] and serviceroles set to [@ziti-ping].

6. Ensure that you have created appropriate edge-router and service-edge-router policies allowing the identities access
   edge-router(s) and the edge-routers access to the service.

7. Download the zpingendpoint1.jwt, zpingendpoint2.jwt

8. Distribute or build the zping binary to or on the endpoint(s) you wish to run on

9. Enroll the endpoints with the zping binary i.e. 
```
    $ ./zping -m enroll -j zitiendpoint1.jwt -o zitiendpoint1.json

      enrolling
[        0.000]    INFO ziti-sdk:ziti_enroll.c:92 ziti_enroll() Ziti C SDK version 0.25.6.66 @ba3938e(main) starting enrollment at (2022-01-31T16:42:30.677)
[        0.000]    INFO ziti-sdk:ziti_ctrl.c:362 ziti_ctrl_init() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] ziti controller client initialized
[        0.132]    INFO ziti-sdk:ziti_enroll.c:41 verify_controller_jwt() verifying JWT signature
[        0.275]    INFO ziti-sdk:ziti_ctrl.c:362 ziti_ctrl_init() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] ziti controller client initialized
[        0.275]    INFO ziti-sdk:ziti_ctrl.c:181 ctrl_default_cb() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] controller supplied new address[demo.openziti.org:443]
[        0.605]    INFO ziti-sdk:ziti_ctrl.c:181 ctrl_default_cb() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] controller supplied new address[demo.openziti.org:443]

Successfully registered and output id to: zitiendpoint1.json
```    
```
    $ ./zping enroll -j zpingendpoint2.jwt -o zpingendpoint2.json 

     enrolling
[        0.000]    INFO ziti-sdk:ziti_enroll.c:92 ziti_enroll() Ziti C SDK version 0.25.6.66 @ba3938e(main) starting enrollment at (2022-01-31T16:42:30.677)
[        0.000]    INFO ziti-sdk:ziti_ctrl.c:362 ziti_ctrl_init() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] ziti controller client initialized
[        0.132]    INFO ziti-sdk:ziti_enroll.c:41 verify_controller_jwt() verifying JWT signature
[        0.275]    INFO ziti-sdk:ziti_ctrl.c:362 ziti_ctrl_init() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] ziti controller client initialized
[        0.275]    INFO ziti-sdk:ziti_ctrl.c:181 ctrl_default_cb() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] controller supplied new address[demo.openziti.org:443]
[        0.605]    INFO ziti-sdk:ziti_ctrl.c:181 ctrl_default_cb() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] controller supplied new address[demo.openziti.org:443]

Successfully registered and output id to: zitiendpoint2.json
```
11. On each machine in run either in background or a separate window in server mode
```
    $ ./zping -m server -c zpingendpoint1.json -s csdk01 &
      Running as server
Connecting using credentials in: zpingendpoint1.json
server=1
[        0.001]    INFO ziti-sdk:ziti.c:376 ziti_init_async() ztx[0] Ziti C SDK version 0.25.6.65 @72323d9(main) starting at (2022-01-31T18:56:06.960)
[        0.001]    INFO ziti-sdk:ziti.c:379 ziti_init_async() ztx[0] Loading from config[winserver03.json] controller[https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443]
[        0.001]    INFO ziti-sdk:ziti_ctrl.c:362 ziti_ctrl_init() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] ziti controller client initialized
[        0.001]    WARN ziti-sdk:ziti.c:742 ziti_re_auth_with_cb() ztx[0] starting to re-auth with ctlr[https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443] api_session_status[0] api_session_expired[TRUE]
[        0.280]    INFO ziti-sdk:ziti.c:1380 version_cb() ztx[0] connected to controller https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443 version v0.23.0(66ddf96a5dc4 2021-11-16 20:44:42)
[        0.280]    INFO ziti-sdk:ziti_ctrl.c:181 ctrl_default_cb() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] controller supplied new address[demo.openziti.org:443]
[        0.414]    INFO ziti-sdk:ziti.c:1270 ziti_set_api_session() ztx[0] api session set, setting api_session_timer to 1740s
[        0.537]    INFO ziti-sdk:channel.c:223 new_ziti_channel() ch[0] (WESTRTR@tls://13.52.3.107:443) new channel for ztx[0] identity[zpingendpoint1]
[        0.537]    INFO ziti-sdk:channel.c:734 reconnect_channel() ch[0] reconnecting NOW
[        0.917]    INFO ziti-sdk:channel.c:635 hello_reply_cb() ch[0] connected. EdgeRouter version: v0.23.0|66ddf96a5dc4|2021-11-16 20:44:42|linux|amd64
Ping Server is ready! 0(OK)          
```
```
      $ ./zping -m server -c zpingendpoint2.json -s csdk01 &
Running as server
Connecting using credentials in: zpingendpoint2.json
server=1
[        0.001]    INFO ziti-sdk:ziti.c:376 ziti_init_async() ztx[0] Ziti C SDK version 0.25.6.65 @72323d9(main) starting at (2022-01-31T18:56:06.960)
[        0.001]    INFO ziti-sdk:ziti.c:379 ziti_init_async() ztx[0] Loading from config[winserver03.json] controller[https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443]
[        0.001]    INFO ziti-sdk:ziti_ctrl.c:362 ziti_ctrl_init() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] ziti controller client initialized
[        0.001]    WARN ziti-sdk:ziti.c:742 ziti_re_auth_with_cb() ztx[0] starting to re-auth with ctlr[https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443] api_session_status[0] api_session_expired[TRUE]
[        0.280]    INFO ziti-sdk:ziti.c:1380 version_cb() ztx[0] connected to controller https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443 version v0.23.0(66ddf96a5dc4 2021-11-16 20:44:42)
[        0.280]    INFO ziti-sdk:ziti_ctrl.c:181 ctrl_default_cb() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] controller supplied new address[demo.openziti.org:443]
[        0.414]    INFO ziti-sdk:ziti.c:1270 ziti_set_api_session() ztx[0] api session set, setting api_session_timer to 1740s
[        0.537]    INFO ziti-sdk:channel.c:223 new_ziti_channel() ch[0] (WESTRTR@tls://13.52.3.107:443) new channel for ztx[0] identity[zpingendpoint2]
[        0.537]    INFO ziti-sdk:channel.c:734 reconnect_channel() ch[0] reconnecting NOW
[        0.917]    INFO ziti-sdk:channel.c:635 hello_reply_cb() ch[0] connected. EdgeRouter version: v0.23.0|66ddf96a5dc4|2021-11-16 20:44:42|linux|amd64
Ping Server is ready! 0(OK)
```
12. Send 5 zpings from zpingclient1 to zpingclient2
```
      $ ./zping -m client -c zpingendpoint1.json -i zpingendpoint2 -n 5 -s csdk01
Running as client
Connecting using credentials in: zpingendpoint1.json
Connecting to identity: zpingendpoint2
[        0.001]    INFO ziti-sdk:ziti.c:376 ziti_init_async() ztx[0] Ziti C SDK version 0.25.6.67 @c36daa4(main) starting at (2022-01-31T18:53:53.008)
[        0.001]    INFO ziti-sdk:ziti.c:379 ziti_init_async() ztx[0] Loading from config[winclient5.json] controller[https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443]
[        0.001]    INFO ziti-sdk:ziti_ctrl.c:362 ziti_ctrl_init() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] ziti controller client initialized
[        0.001]    WARN ziti-sdk:ziti.c:742 ziti_re_auth_with_cb() ztx[0] starting to re-auth with ctlr[https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443] api_session_status[0] api_session_expired[TRUE]
[        0.234]    INFO ziti-sdk:ziti.c:1380 version_cb() ztx[0] connected to controller https://d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io:443 version v0.23.0(66ddf96a5dc4 2021-11-16 20:44:42)
[        0.234]    INFO ziti-sdk:ziti_ctrl.c:181 ctrl_default_cb() ctrl[d05acbdb-4bfc-4d8d-aafc-966bd144325a.production.netfoundry.io] controller supplied new address[demo.openziti.org:443]
[        0.369]    INFO ziti-sdk:ziti.c:1270 ziti_set_api_session() ztx[0] api session set, setting api_session_timer to 1740s
[        0.491]    INFO ziti-sdk:channel.c:223 new_ziti_channel() ch[0] (WESTRTR@tls://13.52.3.107:443) new channel for ztx[0] identity[zpingendpoint1]
[        0.491]    INFO ziti-sdk:channel.c:734 reconnect_channel() ch[0] reconnecting NOW
[        0.854]    INFO ziti-sdk:channel.c:635 hello_reply_cb() ch[0] connected. EdgeRouter version: v0.23.0|66ddf96a5dc4|2021-11-16 20:44:42|linux|amd64
Ping Server Connected!

100 bytes from server ziti_seq=0 time=162.010ms
100 bytes from server ziti_seq=1 time=162.821ms
100 bytes from server ziti_seq=2 time=162.694ms
100 bytes from server ziti_seq=3 time=162.494ms
100 bytes from server ziti_seq=4 time=162.007ms

--- winserver03 ping statistics ---
5 packets sent and 5 packets received, 0.00% packet loss
round-trip min/max/avg/stddev 162.007/162.821/162.405/0.340 ms

[        5.436]    INFO ziti-sdk:ziti.c:489 ziti_shutdown() ztx[0] Ziti is shutting down
[        5.436]    INFO ziti-sdk:channel.c:183 ziti_channel_close() ch[0] closing[WESTRTR@tls://13.52.3.107:443]
unexpected error: ziti context is disabled
[        5.436]    INFO ziti-sdk:ziti.c:489 ziti_shutdown() ztx[0] Ziti is shutting down
ERROR: ev->event.ctx.ctrl_status => ziti context is disabled
```
