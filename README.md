# jwt
A sample extension that demonstrates how to verify and sign JWTs in Go. 

## What's in the sample
A panel that display a button. When the button is clicked, the frontend makes an AJAX call to `/api/ping` with the Twitch-signed JWT in the headers. The EBS verifies the request's JWT and follows up by signing its own JWT.  
The EBS then sends the message `pong` via PubSub with the EBS-signed JWT in the headers. The frontend listens for incoming PubSub messages and outputs `pong` in the console.

## Requirements
- Go 1.10+ with [`dep`](https://github.com/golang/dep) for package management. 
- OpenSSL. If on Windows, you can install Git which bundles it.  

## Installation 
The recommended path to using this sample is with the [Developer Rig](https://github.com/twitchdev/developer-rig).

1. Clone the repo:
`go get github.com/twitchdev/extensions-samples/jwt` 
2. Install dependencies:
`dep ensure`
3. Generate certs for the EBS:
`openssl req -nodes -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX -subj '/CN=localhost'`
4. Set `clientID` and `ownerID` variables in `main.go`


## Usage

1. Host the frontend via the Rig and watch its console: you should see the Twitch-signed JWT printed.
2. Compile the EBS: `go build`
3. Run the EBS: `./jwt -secret=<EXTENSION_SECRET>`
4. Click the "Pong" button.  
5. Watch the EBS console: you should see the EBS-signed JWT printed.
6. You should see "pong" in the Rig console. This means that it has received the PubSub message from the EBS. 
