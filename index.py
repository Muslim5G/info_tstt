from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import hashlib
from secret import *
import uid_generator_pb2
import requests
import struct
import datetime
from flask import Flask, jsonify
import json
from zitado_pb2 import Users
import random
import os

app = Flask(__name__)

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(saturn_, garena):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = saturn_
    message.garena = garena
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, token):
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB49',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = bytes.fromhex(idd)
    response = requests.post('https://clientbp.ggblueshark.com/GetPlayerPersonalShow', headers=headers, data=data)
    hex_response = response.content.hex()
    return hex_response

def token():
    # Load tokens from JSON file
    with open('token_bd.json', 'r') as file:
        tokens = json.load(file)
    # Assuming tokens is a list of dictionaries with 'uid' and 'token' keys
    token_list = [item['token'] for item in tokens]
    random_token = random.choice(token_list)
    return random_token

@app.route('/<uid>', methods=['GET'])
def main(uid):
    saturn_ = int(uid)
    garena = 1
    protobuf_data = create_protobuf(saturn_, garena)
    hex_data = protobuf_to_hex(protobuf_data)
    aes_key = key
    aes_iv = iv
    encrypted_hex = encrypt_aes(hex_data, aes_key, aes_iv)
    tokenn = token()
    infoo = apis(encrypted_hex, tokenn)
    hex_data = infoo
    if not hex_data:
        return jsonify({"error": "hex_data query parameter is missing"}), 400

    try:
        users = decode_hex(hex_data)
    except binascii.Error:
        return jsonify({"error": "Invalid hex data"}), 400

    responses = {}

    if users.basicinfo:
        responses['basicinfo'] = []
        for user_info in users.basicinfo:
            responses['basicinfo'].append({
                'username': user_info.username,
                'region': user_info.region,
                'level': user_info.level,
                'Exp': user_info.Exp,
                'bio': users.bioinfo[0].bio if users.bioinfo else None,
                'banner': user_info.banner,
                'avatar': user_info.avatar,
                'brrankscore': user_info.brrankscore,
                'BadgeCount': user_info.BadgeCount,
                'likes': user_info.likes,
                'lastlogin': user_info.lastlogin,
                'csrankpoint': user_info.csrankpoint,
                'csrankscore': user_info.csrankscore,
                'brrankpoint': user_info.brrankpoint,
                'createat': user_info.createat,
                'OB': user_info.OB
            })

    if users.claninfo:
        responses['claninfo'] = []
        for clan in users.claninfo:
            responses['claninfo'].append({
                'clanid': clan.clanid,
                'clanname': clan.clanname,
                'guildlevel': clan.guildlevel,
                'livemember': clan.livemember
            })

    if users.clanadmin:
        responses['clanadmin'] = []
        for admin in users.clanadmin:
            responses['clanadmin'].append({
                'idadmin': admin.idadmin,
                'adminname': admin.adminname,
                'level': admin.level,
                'exp': admin.exp,
                'brpoint': admin.brpoint,
                'lastlogin': admin.lastlogin,
                'cspoint': admin.cspoint
            })

    responses['Owners'] = ['Muslim', 'Kira']
    
    # إضافة الوقت والتاريخ للمعلومات
    responses['additional_info'] = {
        'current_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
        'timezone': 'EEST',
        'day': 'Friday'
    }
    
    return jsonify(responses), 200

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, port=int(os.environ.get("PORT", 8080)))
