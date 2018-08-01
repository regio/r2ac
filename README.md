This is the source code for a lightweight blockchain prototype, designed to run on constrained devices, allowing to append transactions in exiting blocks. It relies in the pair public/private keys, where each device is identified by its own pair public/private key.

In order to get it running you need at least Python 2.7 and the following dependencies:

-pyCrypto
-flask
-requests
-merkle
-Pyro4

The minimun scenario to run the application should be composed by two gateways where the blockchain is running, a node which will be responsible to run the Pyro4 name server (the proposed chain works with Pyro4 to allow remote objects usage), and N devices that are connected to the gateways producing data.

Name Server:
pyro4-ns -n <Name Server Public IP>

Peers:
r2ac.py <Name Server Public IP>

Devices:
deviceSimulator.py