# interacts with the FPGA's UART interface to provide glitching parameters

import serial
import os 
import logging
import struct
import time
from pyocd.core.helpers import ConnectHelper

TRIALS = 10  # number of trials to do per glitch parameter

class FPGAParameters():
    def __init__(self, port: str, speed: int=115200, delay: int=0, length: int=10):
        """
        Initializes an FPGAParameters object
        :param delay: how long to delay after a trigger before the glitch, in FPGA clock cycles
        :param length: how long to do the glitch for, in FPGA clock cycles
        """
        self.logger = logging.getLogger("FPGAParameters")
        if delay < 0 or length < 0:
            raise ValueError("The delay and/or length must be nonnegative")
        self.delay = delay
        self.length = length
        self.ser = serial.Serial(port, speed, timeout=1)

    def serialize(self) -> bytes:
        """
        Serializes the FPGAParameters to be sent over UART
        """
        # send the delay, then the length, then reset it
        return ((0b10101010).to_bytes(1), b'\0' + struct.pack(">I", self.delay),  b'\xFF' + struct.pack(">B", self.length))

    def send(self):
        """
        Sends the serialized parameters to the FPGA and waits for an ACK
        """
        for packet in self.serialize():
            self.logger.info(f"Sending {packet} to the FPGA")
            self.ser.write(packet)
            res = self.ser.read()
            self.logger.info(f"Got {res} from the FPGA")
            if not res:
                raise Exception("FPGA timed out")

    def close(self):
        """
        Close the serial connection
        """
        self.logger.info("Closing the FGPA serial connection")
        self.ser.close()


class TargetDevice():
    def __init__(self, expected_output: bytes, port: str, speed: int=115200, timeout: int=1):
        """
        :param port: port the serial port of the target device
        """
        self.logger = logging.getLogger("TargetDevice")
        self.expected_output = expected_output
        self.ser = serial.Serial(port, speed, timeout=timeout)

    def set_setup_callback(self, setup):
        """
        Sets the function to be ran for setting up a glitch
        :param setup: the setup function to be ran
        """
        self.logger.debug("Running the setup callback")
        self.setup = setup

    def run(self):
        """
        Runs the program a single time.  Calls the setup callback then waits for input.
        :return: whether or not the glitch was successful
        """
        self.logger.info("Running the program")
        self.setup(self.ser)
        real_output = self.ser.read_all()
        self.logger.info(f"Got the following output {real_output}")
        return self.expected_output in real_output
    
    def close(self):
        """
        Close the serial connection
        """
        self.logger.info("Closing serial connection")
        self.ser.close()


SESSION = ConnectHelper.session_with_chosen_probe(target_override="mspm0l2228")
SESSION.open()
OCD_TARGET = SESSION.board.target
def setup_device(ser: serial.Serial):
    # NOTE: this is part of the tool that is very dependent on the target
    # This example for for targets that just reads at the beginning
    # reset the device
    # subprocess.run(["dslite", "-c", "MSPM0L2228.ccxml", "-r", "1"], stdout=subprocess.DEVNULL)
    OCD_TARGET.dp.reset()
    # clear buffers for a fresh start
    ser.reset_output_buffer()
    ser.reset_input_buffer()
    # read input from file
    program_input = b''
    with open('./input.bin', "rb") as f:  # TODO: change path to actual path
        program_input = f.read()
    ser.write(program_input)


logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.WARNING
)

logging.getLogger("TargetDevice").setLevel(logging.DEBUG)
logging.getLogger("FPGAParameters").setLevel(logging.DEBUG)

# get the expected output from file
with open('./expected.bin', 'rb') as f:  # TODO: make this a command line argument
    expected = f.read()
target = TargetDevice(expected_output=expected, port='/dev/ttyACM0', speed=115200, timeout=1)
target.set_setup_callback(setup_device)
# parameters = FPGAParameters(port='/dev/ttyACM1', speed=115200)  # TODO: change to be the actual FPGA port

# send the parameters to the FPGA
for delay_delta in range(-10, 11):  # -10 to 10, going by 1
    for length in range(8, 13, 2):  # 8 to 12, jumping by 2
        # parameters.send()
        for _ in range(TRIALS):
            if target.run():
                pass
                # print(f"Successful fault with {self.parameters.delay} delay cycles with {self.parameters.length} glitching length cycles")

# Close the serial when done
# parameters.close()
target.close()

SESSION.close()
