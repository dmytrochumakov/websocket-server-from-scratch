import base64
import hashlib
import select
import socket

TCP_IP = "127.0.0.1"
TCP_PORT = 5006
BUFFER_SIZE = 1024 * 1024

DEFAULT_HTTP_RESPONSE = b"""<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\r\n
<TITLE>200 OK</TITLE></HEAD><BODY>\r\n
<H1>200 OK</H1>\r\n
Welcome to the default.\r\n
</BODY></HTML>\r\n\r\n"""

MAGIC_WEBSOCKET_UUID_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_ENDPOINT = "/websocket"


def main():
    tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcpSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcpSocket.bind((TCP_IP, TCP_PORT))
    tcpSocket.listen(1)

    print("listening on port: ", TCP_PORT)

    inputSockets = [tcpSocket]
    outputSockets = []
    xlist = []

    wsSockets = []

    while True:
        readableSockets = select.select(inputSockets, outputSockets, xlist, 5)[0]
        for readySocket in readableSockets:
            if readySocket.fileno() == -1:
                continue

            if readySocket == tcpSocket:
                print("Handling main door socket")
                handleNewConnection(tcpSocket, inputSockets)
            elif readySocket in wsSockets:
                print("this is where we would handle the websocket message")
                handleWebsocketMessage(readySocket, inputSockets, wsSockets)
            else:
                print("Handling regular socket read")
                handleRequest(readySocket, inputSockets, wsSockets)


def handleNewConnection(mainDoorSocket, inputSockets):
    clientSocket, clientAddr = mainDoorSocket.accept()
    print("New socket", clientSocket.fileno(), "from address:", clientAddr)
    inputSockets.append(clientSocket)


def handleRequest(clientSocket, inputSockets, wsSockets):
    print("Handling request from client socket:", clientSocket.fileno())
    message = ""
    while True:
        dataInBytes = clientSocket.recv(BUFFER_SIZE)
        if len(dataInBytes) == 0:
            closeSocket(clientSocket, inputSockets)
            return

        messageSegment = dataInBytes.decode()
        message += messageSegment
        if len(message) > 4 and messageSegment[-4:] == "\r\n\r\n":
            break

    print("Received message:")
    print(message)

    (method, target, httpVersion, headersMap) = parseRequest(message)

    print("method, target, http_version:", method, target, httpVersion)
    print("headers:")
    print(headersMap)

    if target == WS_ENDPOINT:
        print("request to ws endpoint!")
        if isValidWSHandshakeRequest(method, target, httpVersion, headersMap):
            handleWSHandshakeRequest(clientSocket, wsSockets, headersMap)
            return
        else:
            clientSocket.send(b"HTTP/1.1 400 Bad Request")
            closeSocket(clientSocket, inputSockets, wsSockets)
            return

    clientSocket.send(b"HTTP/1.1 200 OK\r\n\r\n" + DEFAULT_HTTP_RESPONSE)
    closeSocket(clientSocket, inputSockets)


def parseRequest(request):
    headersMap = {}

    splitRequest = request.split("\r\n\r\n")[0].split("\r\n")
    [method, target, httpVersion] = splitRequest[0].split(" ")
    headers = splitRequest[1:]

    for headerEntry in headers:
        [header, value] = headerEntry.split(": ")
        headersMap[header.lower()] = value

    return (method, target, httpVersion, headersMap)


def closeSocket(clientSocket, inputSockets, wsSockets):
    print("closing socket")
    if clientSocket in wsSockets:
        wsSockets.remove(clientSocket)
    inputSockets.remove(clientSocket)
    clientSocket.close()
    return


def isValidWSHandshakeRequest(method, target, httpVersion, headersMap):
    isGet = method == "GET"
    httpVersionNumber = float(httpVersion.split("/")[1])
    httpVersionEnough = httpVersionNumber >= 1.1
    headersValid = (
        ("upgrade" in headersMap and headersMap.get("upgrade") == "websocket")
        and ("connection" in headersMap and headersMap.get("connection") == "Upgrade")
        and ("sec-websocket-key" in headersMap)
    )
    return isGet and httpVersionEnough and headersValid


def generateSecWebsocketAccept(secWebsocketKey):
    combined = secWebsocketKey + MAGIC_WEBSOCKET_UUID_STRING
    hashedCombinedString = hashlib.sha1(combined.encode())
    encoded = base64.b64encode(hashedCombinedString.digest())
    return encoded


def handleWSHandshakeRequest(clientSocket, wsSockets, headersMap):
    wsSockets.append(clientSocket)
    secWebsocketAcceptValue = generateSecWebsocketAccept(
        headersMap.get("sec-websocket-key")
    )
    websocketResponse = ""
    websocketResponse += "HTTP/1.1 101 Switching Protocols\r\n"
    websocketResponse += "Upgrade: websocket\r\n"
    websocketResponse += "Connection: Upgrade\r\n"
    websocketResponse += (
        "Sec-WebSocket-Accept: " + secWebsocketAcceptValue.decode() + "\r\n"
    )
    websocketResponse += "\r\n"

    print("\nresponse:\n", websocketResponse)

    clientSocket.send(websocketResponse.encode())


def handleWebsocketMessage(clientSocket, inputSockets, wsSockets):
    dataInBytes = clientSocket.recv(BUFFER_SIZE)
    websocketFrame = WebsocketFrame()
    websocketFrame.populateFromWebsocketFrameMessage(dataInBytes)
    print('Received message:', websocketFrame.getPayloadData().decode('utf-8'))
    return


class WebsocketFrame:

    def populateFromWebsocketFrameMessage(self, dataInBytes):
        self._parseFlags(dataInBytes)
        self._parsePayloadLength(dataInBytes)
        self._maybeParseMaskingKey(dataInBytes)
        self._parsePayload(dataInBytes)

    def _parseFlags(self, dataInBytes):
        firstByte = dataInBytes[0]
        self._fin = firstByte & 0b10000000
        self._rsv1 = firstByte & 0b01000000
        self._rsv2 = firstByte & 0b00100000
        self._rsv3 = firstByte & 0b00010000
        self._opcode = firstByte & 0b00001111

        secondByte = dataInBytes[1]
        self._mask = secondByte & 0b10000000

    def _parsePayloadLength(self, dataInBytes):
        payloadLength = dataInBytes[1] & 0b01111111
        maskKeyStart = 2
        if payloadLength == 126:
            payloadLength = int.from_bytes(
                (bytes(payloadLength) + dataInBytes[2:4]), byteorder="big"
            )
            maskKeyStart = 4
        elif payloadLength == 127:
            payloadLength = int.from_bytes(
                (bytes(payloadLength) + dataInBytes[2:9]), byteorder="big"
            )
            maskKeyStart = 10

        self._payloadLength = payloadLength
        self._maskKeyStart = maskKeyStart

    def _maybeParseMaskingKey(self, dataInBytes):
        if not self._mask:
            return
        self._maskingKey = dataInBytes[self._maskKeyStart : self._maskKeyStart + 4]

    def _parsePayload(self, dataInBytes):
        payloadData = b""
        if self._payloadLength == 0:
            return payloadData

        if self._mask:
            payloadStart = self._maskKeyStart + 4
            encodedPayload = dataInBytes[payloadStart:]
            decodedPayload = [
                byte ^ self._maskingKey[i % 4] for i, byte in enumerate(encodedPayload)
            ]
            payloadData = bytes(decodedPayload)
        else:
            payloadStart = self._maskKeyStart
            payloadData = dataInBytes[payloadStart:]

        self._payloadData = payloadData

    def getPayloadData(self):
        return self._payloadData


if __name__ == "__main__":
    main()
