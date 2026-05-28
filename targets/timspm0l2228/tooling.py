# interacts with the FPGA's UART interface to provide glitching parameters

import pyserial

TRIALS = 10  # number of trials to do per glitch parameter

class FPGAParameters():
    def __init__(self, port: str, speed: int=115200, delay: int=0, length: int=10):
        """
        Initializes an FPGAParameters object
        :param delay: how long to delay after a trigger before the glitch, in FPGA clock cycles
        :param length: how long to do the glitch for, in FPGA clock cycles
        """
        self.delay = delay
        self.length = length
        self.ser = serial.Serial(port, speed, timeout=1)

    def serialize(self) -> bytes
        """
        Serializes the FPGAParameters to be sent over UART
        """
        return b'\0' + struct.pack(">I", self.delay) + b'\xFF' + struct.pack(">B", self.length)

    def send(self):
        """
        Sends the serialized parameters to the FPGA and waits for an ACK
        """
        self.ser.write(self.serialize())
        res = self.ser.read()
        if not res:
            raise Exception("FPGA timed out")

    def close(self):
        """
        Close the serial connection
        """
        self.ser.close()


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
    # get the expected output
    successful_output = b''
    with open('./expected.bin', 'rb') as f:  # TODO: change path to actual
        expected_output = f.read()
    
    # get the real output
    real_output = ser.read()
    return successful_output in real_output:

device_ser = serial.Serial('/dev/ttyACM0', 115200, timeout=1)
parameters = FPGAParameters(port='/dev/ttyACM1', speed=115200)  # TODO: change to be the actual FPGA port

# send the parameters to the FPGA
for i in range(100):
    parameters.send()
    for _ in range(TRIALS):
        reset_device()
        setup_device(device_ser)
        success = check_success(device_ser)
        if success:
            print(f"Successful fault with {self.parameters.delay} delay cycles with {self.parameters.length} glitching length cycles")


# Close the port when done
device_ser.close()
