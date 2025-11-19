#Without Facade Method

class CPU:
    def start(self):
        print("CPU started")

class Memory:
    def load(self):
        print("Memory loaded")

class Disk:
    def read(self):
        print("Disk read")

def main():
    cpu = CPU()
    memory = Memory()
    disk = Disk()

    cpu.start()
    memory.load()
    disk.read()
    print("Computer is ready!")

main()

#With Facade Method

class CPU:
    def start(self):
        print("CPU started")

class Memory:
    def load(self):
        print("Memory loaded")

class Disk:
    def read(self):
        print("Disk read")

class ComputerFacade:
    def start(self):
        cpu = CPU()
        memory = Memory()
        disk = Disk()

        cpu.start()
        memory.load()
        disk.read()
        print("Computer is ready!")


def main():
    computer = ComputerFacade()
    computer.start()  #  one simple call

main()
