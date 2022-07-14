Zitify
======

## What is it?

Zitify is a script that wraps execution of your existing programs and enables it to connect to
[Ziti Services](https://openziti.github.io/ziti/services/overview.html). It brings _app-embeded Ziti_ without any code changes.

## Try the Zitify

Download the latest release and extract into a directory on your `$PATH`

Acquire an enrollment token from [ZEDS](https://zeds.openziti.org)

Enroll (assume your file is `my_id.jwt`). Python is required to execute enrollment command:

```console
$ zitify enroll -j my_id.jwt -i my_id.json
```

Zitify `curl`!

```console
$ export ZITI_IDENTITIES=my_id.json
$ zitify curl http://httpbin.ziti/json
```
