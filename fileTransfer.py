#!/usr/bin/env python
import binascii

def main():
    file = "./test.txt"
    fileToBinary(file)

def fileToBinary(file):
    dataFile = file
    #Get the last item in the delimiter, which should be the filename + extension.
    fileName = file.split("/")[-1]
    binaryDataList = []
    binaryDataString = ""
    tempDataString = ""
    nullChar = "00000000"
    tempString = ""

    with open(dataFile, "rb") as f:
        bytes = bytearray(f.read())

    #For each byte, convert it to binary an concatenate it to a string variable
    #Removes the '0b' beginning to indicate it's binary after each convert.
    for bits in bytes:
        binaryDataString += bin(bits)[2:].zfill(8)

    fileNameList = list(fileName)
    for bits in fileNameList:
        tempDataString += "".join(format(letter,'b').zfill(8) for letter in bytearray(bits))

    #Add null character terminator for separation of filename and file data.
    tempDataString += nullChar + binaryDataString

    #Separate every 8 binary values as a single item in the list.
    i = 0
    n = 8
    binaryDataList = [tempDataString[i:i+n] for i in range(0, len(tempDataString), n)]
    print binaryDataList

    # binaryToFile(binaryDataList)

def binaryToFile(binList):
    nullChar = "00000000"
    dataByteStream = []
    nameByteString = ""
    nameFlag = True

    for byte in binList:
        #Flag checker for the getting the filename.
        if nameFlag:
            if (byte != nullChar):
                nameByteString += byte
            #Denotates the end of the filename data (and start of file data).
            elif (byte == nullChar):
                nameFlag = False
                #Turns the long string of bytes back to ASCII for the filename.
                tempData = int(nameByteString, 2)
                fileName = binascii.unhexlify('%x' % tempData)
        else:
            #Appends every item of 8 bits (byte) to the data byte stream string
            #after converting the value to a decimal from binary.
            dataByteStream.append(int(byte, 2))
    fileDataBytes = bytearray(dataByteStream)

    #Outputs the decoded file to the decodedFiles directory
    with open("./" + "Output_" + fileName, "wa") as w:
        w.write(fileDataBytes)

if __name__ == '__main__':
    main()
