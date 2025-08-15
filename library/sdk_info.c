//
// 	Copyright NetFoundry Inc.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//
#include <uv.h>
#include <internal_model.h>

#if _WIN32
#include <stdint.h>
#include <lmwksta.h>
#include <LMAPIbuf.h>
#pragma comment(lib, "netapi32.lib")

typedef uint32_t in_addr_t;
#define strcasecmp stricmp
#else

#if __APPLE__
#include <sys/sysctl.h>
#endif

#include <arpa/inet.h>
#include <unistd.h>

#if defined(ANDROID)
#include <sys/system_properties.h>
#endif

#endif


static uv_once_t info_once;
static ziti_env_info s_info;
static void ziti_info_init() {
    static uv_utsname_t os_info;
    static char s_hostname[UV_MAXHOSTNAMESIZE];
    static char s_domain[UV_MAXHOSTNAMESIZE];

    uv_os_uname(&os_info);
#if ANDROID
    static char android_release[PROP_VALUE_MAX + 1];
    static char android_version[PROP_VALUE_MAX + 1];
    __system_property_get("ro.build.version.release", android_release);
    __system_property_get("ro.build.version.security_patch", android_version);
    s_info.os = "Android";
    s_info.os_release = android_release;
    s_info.os_version = android_version;
#else
    s_info.os = os_info.sysname;
    s_info.os_release = os_info.release;
    s_info.os_version = os_info.version;

#if __APPLE__
    static char vers[256];
    size_t sz = sizeof vers;
    sysctlbyname("kern.osproductversion", vers, &sz, NULL, 0);
#if TARGET_OS_IPHONE
    s_info.os = "iOS";
#elif TARGET_OS_MAC
    s_info.os = "macOS";
#endif
    s_info.os_release = vers;
    s_info.os_version = os_info.release; // Darwin kernel version
#endif // __APPLE__

#endif
    s_info.arch = os_info.machine;
    size_t len = sizeof(s_hostname);
    uv_os_gethostname(s_hostname, &len);
#if _WIN32
    DWORD domain_len = sizeof(s_domain);
    DWORD rc = 0;
    rc = GetComputerNameExA(ComputerNameDnsDomain, s_domain, &domain_len);

    if (domain_len == 0) {
        WKSTA_INFO_100 *info;
        rc = NetWkstaGetInfo(NULL, 100, (LPBYTE *) &info);
        if (rc == 0) {
            wsprintfA(s_domain, "%ls", info->wki100_langroup);
        }
        NetApiBufferFree(info);
    }
#else
    len = sizeof(s_domain);
    if (getdomainname(s_domain, (int)len) != 0) {
        s_domain[0] = '\0'; // no domain name available
    }
#endif

    s_info.hostname = s_hostname;
    s_info.domain = s_domain;
}

const ziti_env_info* get_env_info() {
    uv_once(&info_once, ziti_info_init);

    return &s_info;
}

void ziti_set_device_id(const char *device_id) {
    free((void*)s_info.device_id);
    s_info.device_id = NULL;

    if (device_id) {
        s_info.device_id = strdup(device_id);
    }
}
