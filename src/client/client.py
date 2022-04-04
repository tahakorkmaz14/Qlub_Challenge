import os
import sys
import asyncio
import websockets
from websockets.exceptions import ConnectionClosedError
import json
from utils.rsa import encrypt as rsa_encrypt
from utils.aes import encrypt, decrypt

current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Should've used config file
password = "password"
rsa_key = "id_rsa.pub"
url = "ws://localhost:3000/order"


async def start_webservice():
    headers = {"Authentication": rsa_encrypt(password, rsa_key)}
    async with websockets.connect(url, extra_headers=headers) as ws:
        key = ws.response_headers["Token"]
        while True:
            try:
                await ws.send(prepare_data("Hello World", key))
                response = await ws.recv()
                data = parse_response(response, key)
                print(data)
                await asyncio.sleep(5)
            except ConnectionClosedError:
                print(f"Websocket connection closed")
                break

"""Decrypts the Data received from the server
Arguments:
    response (json): encrypted json data from server as response

Returns:
    json: Decrypted json data
"""
def parse_response(response, key):

    response = json.loads(response)
    iv = response["iv"]
    encrypted_message = response["message"]
    decrypted_message = decrypt(encrypted_message, key, iv)
    return {"message": decrypted_message}


"""Encrypts the Data for Sending using AES
Arguments:
    message (_type_): Message to be sent
    key (_type_): Key to use for encryption

Returns:
    json : json data can be sent for server
"""
def prepare_data(message, key):

    output = encrypt(message, key)
    return json.dumps({"message": output[0], "iv": output[1]})


asyncio.run(start_webservice())
