// Copyright (c) 2023.  NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#ifndef ZITI_SDK_CONNECT_H
#define ZITI_SDK_CONNECT_H

#ifdef __cplusplus
extern "C" {
#endif


#define conn_states(XX) \
    XX(Initial)\
    XX(Connecting)\
    XX(Connected)\
    XX(Accepting)\
    XX(CloseWrite)\
    XX(Timedout)\
    XX(Disconnected)\
    XX(Closed)

enum conn_state {
#define state_enum(ST) ST,
    conn_states(state_enum)
};

void init_transport_conn(struct ziti_conn *conn);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_CONNECT_H
