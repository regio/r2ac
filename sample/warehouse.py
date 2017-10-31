from __future__ import print_function
import Pyro4
import socket


@Pyro4.expose
@Pyro4.behavior(instance_mode="single")
class Warehouse(object):
    def __init__(self):
        self.contents = ["chair", "bike"]

    def list_contents(self):
        return self.contents

    def take(self, name, item):
        self.contents.remove(item)
        print("{0} took the {1}.".format(name, item))

    def store(self, name, item):
        self.contents.append(item)
        print("{0} stored the {1}.".format(name, item))


def getMyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myIP = s.getsockname()[0]
    s.close()
    return myIP

def main():
    Pyro4.config.HOST = str(getMyIP())
    Pyro4.Daemon.serveSimple(
            {
                Warehouse: "example.warehouse"
            },
            ns = False)

if __name__=="__main__":
    main()