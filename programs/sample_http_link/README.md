# Sample HTTP Link

## OpenZiti Concepts Demonstrated
This sample demonstrates some key OpenZiti concepts:
* Application-embedded zero trust client.
* Offloading traffic from an identity. OpenZiti allows you to configure a tunneler to offload traffic towards another. This sample offloads traffic from a router to http://httpbin.org using a `host.v1` config.
* Using a `host.v1` config to specify an address and port to dial in order to reach the service
* Creating a service and adding a single (host) config to configure the service.
* Service Policies to authorize identities to perform `dial` or `bind`.

## Prerequisites
You'll want to follow the steps in [BUILD.md](../../BUILD.md) to compile the sample programs.

## Setup
### Create Identities
There will be one identity for the server side, hosting the server, and another for the client side, which will be 
allowed to reach (dial) the service.

We will need a host and client identity. If you already have a network with identities, you can reuse them, just 
ensure you update the attributes. Here's how you would generate them.
```
ziti edge create identity device httpbin.server -a httpbinServerEndpoints -o httpbin.server.jwt
ziti edge create identity device httpbin.client -a httpbinClientEndpoints -o httpbin.client.jwt
```
### Enroll The Identities
The identities need to be [enrolled](https://openziti.io/docs/learn/core-concepts/identities/enrolling) so the 
controller knows about them.
```
ziti edge enroll httpbin.server.jwt
ziti edge enroll httpbin.client.jwt
```

### Create A Host Service Config
It is easier to create the service config before the actual service. The config can then be supplied when creating the 
service.
```
ziti edge create config httpbin-host.v1 host.v1 '{"protocol":"tcp", "address":"httpbin.org","port":80}'
```
### Create A Service
Create a service and attach the previously created host config using the `--configs` flag.
```
ziti edge create service httpbin --configs httpbin-host.v1
```
### Create Service Policies
Lastly, we need to create service policies. Service policies define which identities interact with which services, and 
the actions they are authorized to perform on a service. In this case, we create a Bind policy that allows identities 
with the `httpbinServerEndpoints` attribute to bind to this service. The Dial policy defines which identities can dial 
the service. In this case, any identity with the `httpbinClientEndpoints` attribute can dial this service.
```
ziti edge create service-policy httpbin-binding Bind --service-roles '@httpbin' --identity-roles '#httpbinServerEndpoints'
ziti edge create service-policy httpbin-dialing Dial --service-roles '@httpbin' --identity-roles '#httpbinClientEndpoints'
```

## Start A Tunneler
Download the appropriate Ziti Tunneler for your operating system [here](https://github.com/openziti/ziti-tunnel-sdk-c/releases/latest).

Start the tunneler, providing it with the server identity file (`httpbin.server.json`). Be sure to update the path to 
point to your identity file as necessary. The tunneler will handle offloading traffic from the OpenZiti network to its 
final destination (http://httpbin.org).
```
sudo ./ziti-edge-tunnel run -i httpbin.server.json
```
## Run The Sample
Run the sample, providing it with the client identity file (`httpbin.client.json`). Be sure to update the path to point 
to your identity file as necessary
```
./sample_http_link httpbin.client.json
```
## Cleanup
To clean up the network, use the following commands
```
# Remove Service Policies
ziti edge delete service-policies httpbin-binding httpbin-dialing
# Remove the Service
ziti edge delete service httpbin
# Remove the confgs
ziti edge delete configs httpbin-host.v1
# Remove the identities
ziti edge delete identities httpbin.client httpbin.server
```