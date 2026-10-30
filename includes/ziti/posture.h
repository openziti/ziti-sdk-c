// Copyright (c) 2022-2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @file posture.h
 * @brief Posture query and response callbacks, and the host state change signal.
 */

#ifndef ZITI_POSTURE_H
#define ZITI_POSTURE_H

#include <stdbool.h>

#include "externs.h"
#include "handles.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Posture response MAC address callback
 *
 * This callback should be invoked after gathering the relevant MAC Addresses
 * available during a ziti_pq_mac_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query this response answers, as received by ziti_pq_mac_cb()
 * @param mac_addresses an array of the mac addresses the host currently has access to. Values should be hex strings. Nil signifies not supported.
 * @param num_mac the size of the mac_addresses array
 *
 * @see ziti_pq_mac_cb()
 */
typedef void (*ziti_pr_mac_cb)(ziti_context ztx, const char *id, char **mac_addresses, int num_mac);

/**
 * @brief Posture Query for MAC addresses callback
 *
 * This callback is invoked when the MAC addresses of the current host are needed.
 * The callback will be supplied a followup callback to supply an array of
 * MAC Addresses.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query to answer, to be passed on to response_cb
 * @param response_cb the callback to invoke to supply values
 *
 * @see ziti_pr_mac_cb
 */
typedef void (*ziti_pq_mac_cb)(ziti_context ztx, const char *id, ziti_pr_mac_cb response_cb);

/**
 * @brief Posture response Domain callback
 *
 * This callback should be invoked after gathering the relevant Domain
 * of the host during a ziti_pq_domain_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query this response answers, as received by ziti_pq_domain_cb()
 * @param domain the domain the host has joint or nil if not supported
 *
 *  @see ziti_pq_domain_cb()
 */
typedef void (*ziti_pr_domain_cb)(ziti_context ztx, const char *id, const char *domain);

/**
 *  @brief Posture Query for Domain callback
 *
 * This callback is invoked when the Domain of the current host is needed.
 * The callback will be supplied a followup callback to supply the host's domain.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query to answer, to be passed on to response_cb
 * @param response_cb the callback to invoke to supply values
 *
 * @see ziti_pr_domain_cb
 */
typedef void (*ziti_pq_domain_cb)(ziti_context ztx, const char *id, ziti_pr_domain_cb response_cb);

/**
 * @brief Posture response OS callback
 *
 * This callback should be invoked after gathering the relevant OS versions
 * of the host during a ziti_pq_os_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query this response answers, as received by ziti_pq_os_cb()
 * @param os_type the OS type: Windows, Linux, Android, macOS, iOS
 * @param os_version the OS version or kernel version
 * @param os_build the build of the OS or nil if not supported
 *
 * @see ziti_pq_os_cb()
 */
typedef void (*ziti_pr_os_cb)(ziti_context ztx, const char *id, const char *os_type, const char *os_version, const char *os_build);

/**
 *  @brief Posture Query for OS callback
 *
 * This callback is invoked when the OS version info of the current host is needed.
 * The callback will be supplied a followup callback to supply the host's OS information.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query to answer, to be passed on to response_cb
 * @param response_cb the callback to invoke to supply values
 *
 * @see ziti_pr_os_cb
 */
typedef void (*ziti_pq_os_cb)(ziti_context ztx, const char *id, ziti_pr_os_cb response_cb);


/**
 *  @brief Posture response process callback
 *
 *  This callback should be invoked after gathering the relevant process information
 *  from the host during a ziti_pq_process_cb()
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query this response answers, as received by ziti_pq_process_cb()
 * @param path the path of the inspect process
 * @param is_running if the process is running
 * @param sha_512_hash the sha512 hash of the process's binary file
 * @param signers sha1 hex string fingerprints of the binary or nil if not supported
 * @param num_signers the number of signers
 *
 *  @see ziti_pq_process_cb()
 */
typedef void(*ziti_pr_process_cb)(ziti_context ztx, const char *id, const char *path, bool is_running,
                                  const char *sha_512_hash, char **signers, int num_signers);

/**
 *  @brief Posture Query for process callback
 *
 * This callback is invoked when process info is needed from the host.
 * The callback will be supplied a followup callback to supply the process's status
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param id the id of the posture query to answer, to be passed on to response_cb
 * @param path the process path to inspect
 * @param response_cb the callback to invoke
 *
 * @see ziti_pr_process_cb
 */
typedef void (*ziti_pq_process_cb)(ziti_context ztx, const char *id, const char *path,
                                   ziti_pr_process_cb response_cb);

/**
 * @brief Alerts that the host running the `ziti_context` has undergone a state change.
 *
 * Notifies that the host has undergone a state change: either woke or unlocked.
 * Being "woke" is defined as the screen dimming/shutting off
 * Being "unlocked" is defined as having the device unlocked via a security mechanism.
 *
 * At one time, a device may be "woken" and "unlocked".
 *
 * A context that is not authenticated, and waits for the SDK to authenticate it again (the network was away, and the SDK
 * backs off between its attempts), takes the state change as a sign that the network may be back and does not wait
 * for the next attempt.
 *
 * @param ztx the handle to the Ziti Edge identity context needed for other Ziti C SDK functions
 * @param woken whether the host device has been woke from sleep/hibernation
 * @param unlocked whether the host device has been unlocked
 */
ZITI_FUNC
extern void ziti_endpoint_state_change(ziti_context ztx, bool woken, bool unlocked);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_POSTURE_H */
