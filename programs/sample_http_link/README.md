#Running Sample HTTP Link
##Setup Identities
###Create Identities
We will create a host and client identity.

For the purposes of this example and for the purpose of brevity we will create the device identities and configure the endpoints all in one command though this can be done separately.
```
ziti edge create identity device httpbin.server -a httpbinServerEndpoints -o httpbin.server.jwt
ziti edge create identity device httpbin.client -a httpbinClientEndpoints -o httpbin.client.jwt
```
###Enroll The Identities
We now have to enroll the identities so the controller knows about them.
```
ziti edge enroll httpbin.server.jwt
ziti edge enroll httpbin.client.jwt
```
##Set Up The Service
### Create A Service Config
We'll create the service config before the actual service so that we can pass in the config when we create the service. This will save extra steps.
```
ziti edge create config httpbin-host.v1 host.v1 '{"protocol":"tcp", "address":"httpbin.org","port":80}'
```
###Create A Service
Create a service to allow access the network traffic.
```
ziti edge create service httpbin --configs httpbin-host.v1
```
###Create Service Policies
Lastly, we need to create service policies. The service policies define which identities can interact with certain services and how they interact with those services.  which edge routers are used to do so.
```
ziti edge create service-policy httpbin-binding Bind --service-roles '@httpbin' --identity-roles '#httpbinServerEndpoints'
ziti edge create service-policy httpbin-dialing Dial --service-roles '@httpbin' --identity-roles '#httpbinClientEndpoints'
```

##Start A Tunneler
Download the appropriate Ziti Tunneler for your operating system [here](https://github.com/openziti/ziti-tunnel-sdk-c/releases/latest).

Start the tunneler, providing it with the server identity file (`httpbin.server.json`). Be sure to update the path to your identity file if necessary.
```
sudo ./ziti-edge-tunnel run -i httpbin.server.json
```
##Run The Sample
If you haven't already, you will need to build the C SDK. Follow the steps [here](https://github.com/openziti/ziti-sdk-c/blob/main/building.md)
###Using CLion
Update the run configuration by adding the path to your client json identity file to the "Program Arguments" section.
###Using CLI
Navigate to the folder with the executable, located in the project folder `build/programs/sample_http_link/`

Run the executable, providing it with the path to your `httpbin.client.json` identity file