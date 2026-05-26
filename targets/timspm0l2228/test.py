# this file sends a binary file over UART to the device and prints the output to screen

import serial

# Open the serial port (example: COM3 on Windows or /dev/ttyUSB0 on Linux)
ser = serial.Serial('/dev/ttyACM0', 115200, timeout=1)

# Write data (must be in bytes)
ser_in = b''
with open("../../outputs/pc_test/solved_pc_45.bin", "rb") as f:
    ser_in = f.read()  # Returns a bytes object
ser.write(ser_in)

# Read a line of data
line = ser.readline()
print(line)

# Close the port when done
ser.close()
