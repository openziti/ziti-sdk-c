This overlay drops `cli` from botan's `--build-targets`, so only the static/shared library is
built (which is all `botan::botan-static` in `tests/integ/CMakeLists.txt` needs).

It exists because newer macOS SDKs have removed the `kSBXProfileNoWriteExceptTemporary`
constant declaration from `sandbox.h`, and botan's CLI (`src/cli/sandbox.cpp`) references it
directly, breaking the build:

```
error: use of undeclared identifier 'kSBXProfileNoWriteExceptTemporary'
   if(::sandbox_init(kSBXProfileNoWriteExceptTemporary, SANDBOX_NAMED, nullptr) < 0) {
```

`sandbox_init()` and its named-profile constants were deprecated by Apple back in macOS 10.8;
this SDK is the first to actually strip the constant declarations rather than just flag them
deprecated. The `#include <sandbox.h>` compiled in this file is Apple's system header, not
botan's own `sandbox.h` (which sits next to `sandbox.cpp` and just declares the `Sandbox`
class) -- there's no local header to patch. Since this file is compiled only for the `cli`
target, skipping `cli` entirely sidesteps the break rather than working around it.

**Remove this overlay once either:**
- botan's `sandbox.cpp` stops referencing the removed constant (upstream fix -- check
  https://github.com/randombit/botan/blob/master/src/cli/sandbox.cpp), or
- the vcpkg botan port bumps past the version that carries the broken code, with the fix
  included.

Until then, keep this in sync with upstream's `ports/botan/portfile.cmake` whenever the pinned
botan version changes -- diff against `$VCPKG_ROOT/ports/botan/portfile.cmake` and reapply the
two `--build-targets=shared`/`--build-targets=static` edits (dropping `,cli`) and the removed
`vcpkg_copy_tools(TOOL_NAMES botan AUTO_CLEAN)` call.
