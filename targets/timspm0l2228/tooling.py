# interacts with the FPGA's UART interface to provide glitching parameters

import pyserial

class FPGAParameters():
    def __init__(self, port: str, speed: int=115200, wait: int=0, period: int=10):
        """
        Initializes an FPGAParameters object
        :param wait: how long to wait after a trigger before the glitch, in FPGA clock cycles
        :param period: how long to do the glitch for, in FPGA clock cycles
        """
        self.wait = wait
        self.period = period
        self.ser = serial.Serial(port, speed, timeout=1)

    def serialize(self) -> bytes
        """
        Serializes the FPGAParameters to be sent over UART
        """
        return struct.pack(">II", self.wait, self.period)

    def send(self):
        """
        Sends the serialized parameters to the FPGA and waits for an ACK
        """
        self.ser.write(self.serialize())
        res = self.ser.read()
        if not res:
            raise Exception("FPGA timed out")

def reset_device():
    subprocess.run("dslite -c MSPM0L2228.ccxml -r 1")

def setup_device(ser: serial.Serial):
    # NOTE: this is part of the program that is very dependent on the target
    # This example for for a very simple binary that just sends data at the beginning
    # read input from file
    program_input = b''
    with open('./input.bin', "rb") as f:  # TODO: change path to actual path
        program_input = f.read()
    ser.write(program_input)

def check_success(ser: serial.Serial) -> bool:
    """
    Checks if a fault resulted in a proper security fault
    :param ser: the serial object for the device being hacked
    """


device_ser = serial.Serial('/dev/ttyACM0', 115200, timeout=1)
parameters = FPGAParameters(port='/dev/ttyACM1', speed=115200)  # TODO: change to be the actual FPGA port


# send the intial parameters
parameters.send()
# reset_device
reset_device()


# Close the port when done
ser.close()

