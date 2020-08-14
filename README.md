# RandomServer
 
RandomServer is half of a project i'm working on to kill boredom of the masses.

*enter me*

The purpose of RandomServer is to allow any average joe to set up a random server and allow other average joe's to send him stuff using RandomClient (https://github.com/Sudnym/RandomClient).

# The How

RandomServer uses gnet (https://github.com/panjf2000/gnet) to set up a server that awaits connections and uses diffie hellman key exchange (https://github.com/monnand/dhkx) to create e2e encryption, and then the server recieves a message, and sends the message to the terminal.

# The Why

Why not? Set one up, see what you get!

# Setup

The moment you have all been waiting for! Setup instructions!

Step 1: Download the RandomClient repository.

Step 2: If you have a windows amd64 device, or a linux amd64 device, you can skip to step 5b for windows and step 5c for linux

Step 3: If you don't have a windows or linux amd64 device, you need to install golang here: https://golang.org/dl/

Step 4: Once golang is installed, open a terminal and navigate to the RandomServer repository.

Step 5a: Run `go build RandomServer.go` skip Step 5b.

Step 5b: Open the repository and double click on the RandomServer.exe file. Skip Step 5c.

Step 5c: Open a terminal, navigate to the repository, and run `RandomServer`

Step 6: RandomServer is now running and will work within your LAN. If you would like the outside world to be able to access your RandomServer continue to the next step.

Step 7: Open a terminal window and run for windows: `ipconfig` for linux: `iwconfig` or `ifconfig`, for any other device search how to find IP address in terminal.

Step 8: Locate your device's IP address, and port forward port 9000 from your IP address to port 9000 on your router.

Step 9: Test your port forward by installing and running RandomClient and googling "my ip" and using the IP that google shows.


# The Client

https://github.com/Sudnym/RandomClient
