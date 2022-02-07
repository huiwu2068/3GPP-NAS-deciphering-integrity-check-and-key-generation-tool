from ctypes import sizeof
import tkinter
from tkinter.filedialog import askopenfilename
import threading
import queue
from tkinter.tix import INTEGER
from Crypto.Hash import HMAC, SHA256, CMAC
from Crypto.Cipher import AES
import pyshark
import sys
import os.path
import subprocess
from datetime import datetime
from time import sleep as module_time_sleep
import logging
import logging.handlers
from CryptoMobile.Milenage import Milenage
#from CryptoMobile.CMAC import CMAC
#from CryptoMobile.AES import AES_ECB, AES_CTL
import configparser
import socket
import struct
# import traceback
import pysnow
import pyzuc
from logging.handlers import QueueHandler
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

logging.basicConfig()
logger = logging.getLogger(name="decipher")     # get logger instance .
ngap_procedurecode_dict ={
}

nas_5gs_mm_message_dict ={
#5GS mobility management messages
'41':('Registration request','UL'),
'42':('Registration accept','DL'),
'43':('Registration complete','UL'),
'44':('Registration reject','DL'),
'45':('Deregistration request (UE originating)','DL'),
'46':('Deregistration accept (UE originating)','DL'),
'47':('Deregistration request (UE terminated)','DL'),
'48':('Deregistration accept (UE terminated	','UL'),
'4c':('Service request','UL'),
'4d':('Service reject','DL'),
'4e':('Service accept','DL'),
'4f':('Control plane service request','UL'),
'50':('Network slice-specific authentication command','DL'),
'51':('Network slice-specific authentication complete','UL'),
'52':('Network slice-specific authentication result','DL'),
'54':('Configuration update command','DL'),
'55':('Configuration update complete','UL'),
'56':('Authentication request','DL'),
'57':('Authentication response','UL'),
'58':('Authentication reject','DL'),
'59':('Authentication failure','UL'),
'5a':('Authentication result','DL'),
'5b':('Identity request','DL'),
'5c':('Identity response','UL'),
'5d':('Security mode command','DL'),
'5e':('Security mode complete','UL'),
'5f':('Security mode reject','UL'),
'64':('5GMM status','BOTH'),
'65':('Notification','DL'),
'66':('Notification response','UL'),
'67':('UL NAS transport','UL'),
'68':('DL NAS transport','DL'),
#5GS session management messages
'c1':('PDU session establishment request','UL'),
'c2':('PDU session establishment accept','DL'),
'c3':('PDU session establishment reject','DL'),
'c5':('PDU session authentication command','DL'),
'c6':('PDU session authentication complete','UL'),
'c7':('PDU session authentication result','DL'),
'c9':('PDU session modification request','UL'),
'ca':('PDU session modification reject','DL'),
'cb':('PDU session modification command','DL'),
'cc':('PDU session modification complete','UL'),
'cd':('PDU session modification command reject','UL'),
'd1':('PDU session release request','UL'),
'd2':('PDU session release reject','DL'),
'd3':('PDU session release command','DL'),
'd4':('PDU session release complete','UL'),
'd5':('5GSM status','BOTH')
}
class Ue:
    def __init__(self,supi=None):
        self.supi:bytes = supi
        self.ue_dict={}
        if(supi != None):
            self.ue_dict['supi'] = supi.decode('ascii')
        else:
            self.ue_dict['supi'] = None
        self.key: bytes = None            # bytes string.
        self.op: bytes = None             # bytes string.
        self.nas_5gs_5g_tmsi: bytes = b''
        self.nas_5gs_amf_id =  None
    
        self.ue_dict['downlink_nas_overflow'] = 0
        self.ue_dict['uplink_nas_overflow'] = 0
        self.ue_dict['encryption_algorithm_id'] = '0'
        self.ue_dict['integrity_algorithm_id'] = '2'

    def SetIpInfo(self,gnb_ip,ran_ue_ngap_id, amf_ip,amf_ue_ngap_id=None):
        self.gnb_ip:str = gnb_ip
        self.ran_ue_ngap_id:str = ran_ue_ngap_id        
        self.amf_ip:str = amf_ip 
        self.amf_ue_ngap_id:str = amf_ue_ngap_id 

    def read_config_Info(self):
        if 'supi' in self.ue_dict and self.ue_dict['supi']!=None:
            self.supi:bytes = self.ue_dict['supi'].encode('ascii')
        if 'nas_5gs_5g_tmsi' in self.ue_dict:
            self.nas_5gs_5g_tmsi: bytes = bytes.fromhex(self.ue_dict['nas_5gs_5g_tmsi'])
        if 'key' in self.ue_dict:
            self.key: bytes = bytes.fromhex(self.ue_dict['key'])
        if 'op' in self.ue_dict:
            self.op: bytes = bytes.fromhex(self.ue_dict['op'])
        if 'downlink_nas_overflow' in self.ue_dict:
            self.ue_dict['downlink_nas_overflow'] = int(self.ue_dict['downlink_nas_overflow'])
        if 'uplink_nas_overflow' in self.ue_dict:
            self.ue_dict['uplink_nas_overflow'] =int(self.ue_dict['uplink_nas_overflow'])

class Decryption:
    def __init__(self,decrypt_suci, private_key, secret_key,
                 use_op, op, opc, file_location, _queue,tshark_path,new_bearer_id):
        """
                self.ue_dict contains all data for each UE like ngap_id,rand,encryption key,RES,use SUPI as index.
                It's a three dimensionals dictionary and key in first level is ran-UE-ngap-ID, key in second
                level dict is GNB-IP,third level dictionary contains a single UE's all kinds of data.
                self.ue_dict structure: {"ran-UE-ngap-ID":{"GNB-IP":{AMF-UE-ngap-ID":"xxxx",encrytion key:"xxxx",
                rand:"xxxx",res:"xxxx",mac:"xxxx",.....}}}
                self.ue_dict:
                mcc:string of 3 digits base 10
                mnc:string of 3 digits base 10,padded by 0 in the front if it's 2 digits.
                supi:string of 15 digits base 10, need to convert to ascii before usage.
                ran-UE-ngap-id: string of hex digits.
                rand,res,ck,ik: bytes string.
                snn: string of network name.
                kausf/kseaf/kamf/cipher_key: bytes string.
                algorithm_id: string of 1 digit based 10.
                local_downlink_nas_count: integer
                local_uplink_nas_count: integer
            """
        self.decrypt_suci = decrypt_suci
        self.private_key: bytes = private_key          # bytes string.
        self.secret_key: bytes = secret_key            # bytes string.
        self.use_op = use_op
        self.OP: bytes = op                            # bytes string.
        self.OPC: bytes = opc                          # bytes string.
        self.file_location = file_location
        self.queue = _queue
        self.TIME_OUT_FILTER_PCAP= 300
        #self.ue_dict = {}
        self.amf_ip_list = []
        self.buffer = None
        self.capture = None #the capture object genereated by pyshark.Capture
        self.filtered_file_name =None
        self.tshark_path = tshark_path
        self.new_bearer_id= new_bearer_id
        self.ue_list = []
        self.ue_temp_list = []

    def create_temp_ue(self,gnb_ip,ran_ue_ngap_id,amf_ip):
        if gnb_ip is not None and ran_ue_ngap_id is not None:
            ue = Ue()
            ue.SetIpInfo(gnb_ip,ran_ue_ngap_id,amf_ip)
        return ue

    def copy_Ue_from_tempUe(self,ue,ue_temp):
        ue.gnb_ip = ue_temp.gnb_ip
        ue.ran_ue_ngap_id = ue_temp.ran_ue_ngap_id
        ue.amf_ip = ue_temp.amf_ip
        ue.amf_ue_ngap_id = ue_temp.amf_ue_ngap_id
        if ue_temp.nas_5gs_5g_tmsi is not None:
            ue.nas_5gs_5g_tmsi = ue_temp.nas_5gs_5g_tmsi
        if ue_temp.nas_5gs_amf_id is not None:
            ue.nas_5gs_amf_id = ue_temp.nas_5gs_amf_id
        if 'mcc' in ue_temp.ue_dict:
            ue.ue_dict['mcc'] = ue_temp.ue_dict['mcc']
            ue.ue_dict['mnc'] = ue_temp.ue_dict['mnc']
            ue.ue_dict['snn'] = ue_temp.ue_dict['snn']
        if 'kseaf' in ue_temp.ue_dict:
            ue.ue_dict['kseaf'] = ue_temp.ue_dict['kseaf']

        if 'local_downlink_nas_count' in ue_temp.ue_dict:
            ue.ue_dict['local_downlink_nas_count'] = ue_temp.ue_dict['local_downlink_nas_count']
            ue.ue_dict['local_uplink_nas_count'] = ue_temp.ue_dict['local_uplink_nas_count']
        return True

    def merge_tempUe_to_Ue(self,ue_temp,service_req = False):
        supi_found = False
        if 'supi' in ue_temp.ue_dict and ue_temp.ue_dict['supi']!= None:
            for ue in self.ue_list:
                if ue_temp.ue_dict['supi'] == ue.ue_dict['supi']:
                    supi_found = True
                    break
            if supi_found == False:
                ue = Ue(ue_temp.ue_dict['supi'].encode('ascii'))
                self.ue_list.append(ue)
                #ue_temp is not added to ue_temp_list for default
                supi_found = True
        else:
            for ue in self.ue_list: #supi in config file or The UE has been the network
                if(ue_temp.nas_5gs_5g_tmsi == ue.nas_5gs_5g_tmsi):
                    if(ue.nas_5gs_amf_id == None):#Simplify manual configuration files
                        supi_found = True
                    elif ((not service_req) and ue_temp.nas_5gs_amf_id == ue.nas_5gs_amf_id):
                        supi_found = True
                    elif service_req and (ue_temp.nas_5gs_amf_id&0x00FF) == (ue.nas_5gs_amf_id&0x00FF):
                        supi_found = True
                    break
        if(supi_found):
            self.copy_Ue_from_tempUe(ue,ue_temp)
            return supi_found,ue
        else:
            return supi_found,None

    #The UE uses TMSI to repeatedly access the network, update and print the change of gnb ngap id
    def merge_tempUe(self,ue_temp,service_req):
        tmsi_found = False
        ue = None
        for ue in self.ue_temp_list:
            if(ue_temp.nas_5gs_5g_tmsi == ue.nas_5gs_5g_tmsi):
                if ((not service_req) and ue_temp.nas_5gs_amf_id == ue.nas_5gs_amf_id):
                    tmsi_found = True
                elif service_req and (ue_temp.nas_5gs_amf_id&0x00FF) == (ue.nas_5gs_amf_id&0x00FF):
                    tmsi_found = True
                break
        if(tmsi_found):
            logger.info(f"5g_tmsi:{ue_temp.nas_5gs_5g_tmsi.hex()},"
                f"new ue ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue_temp.gnb_ip,16))))},ngapid:{int(ue_temp.ran_ue_ngap_id,16)},"
                f"old ue ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))},ngapid:{int(ue.ran_ue_ngap_id,16)}")
            return tmsi_found,ue
        else:
            logger.info(f"5g_tmsi:{ue_temp.nas_5gs_5g_tmsi.hex()},"
                f"new ue ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue_temp.gnb_ip,16))))},ngapid:{int(ue_temp.ran_ue_ngap_id,16)},"
                f"old ue none")
            return tmsi_found,None

    def get_ue_for_ngap(self,gnb_ip,ran_ue_ngap_id):
        ue_found = False
        ue_temp = None
        if ran_ue_ngap_id is not None and gnb_ip is not None:
            for ue_temp in self.ue_list:
                if not (hasattr(ue_temp,'gnb_ip') and hasattr(ue_temp,'ran_ue_ngap_id')):
                    continue
                if ue_temp.gnb_ip == gnb_ip and ue_temp.ran_ue_ngap_id == ran_ue_ngap_id:
                    ue_found = True
                    return ue_found, ue_temp
        return ue_found,ue_temp

    def get_temp_ue_for_ngap(self,gnb_ip,ran_ue_ngap_id):
        ue_found = False
        ue_temp = None
        if ran_ue_ngap_id is not None and gnb_ip is not None:
            for ue_temp in self.ue_temp_list:
                if not (hasattr(ue_temp,'gnb_ip') and hasattr(ue_temp,'ran_ue_ngap_id')):
                    continue
                if ue_temp.gnb_ip == gnb_ip and ue_temp.ran_ue_ngap_id == ran_ue_ngap_id:
                    ue_found = True
                    return ue_found, ue_temp
        return ue_found,ue_temp

    def call_milenage(self,sk, op:bytes, opc:bytes,rand, autn, sqn_xor_ak, amf, retrieved_mac):
        # need enhancement here to handle OPc.

        if opc:
            mil = Milenage(b'00')
            mil.set_opc(opc)
        elif op:
            mil = Milenage(op)
        else:
            return None,None,None


        res, ck, ik, ak = mil.f2345(sk, rand)
        # get sqn by ak xor sqn_xor_ak
        sqn = (int.from_bytes(ak, byteorder='big') ^
               int.from_bytes(sqn_xor_ak, byteorder="big")).to_bytes(6, byteorder='big')
        computed_mac = mil.f1(sk, rand, sqn, amf)
        if computed_mac == retrieved_mac:
            return res, ck, ik
        else:
            logger.warning("mac failure! one authentication request message skipped!")
            return None, None, None

    def get_tshark_path(self,tshark_path=None):
        """
            Finds the path of the tshark executable. If the user has provided a path
            it will be used. Otherwise default locations will be searched.

            :param tshark_path: Path of the tshark binary
            :raises TSharkNotFoundException in case TShark is not found in any location.
        """
        possible_paths = [r'C:\Program Files\Wireshark\tshark.exe',r'D:\Program Files\Wireshark\tshark.exe']
        if self.tshark_path:
            possible_paths.insert(0, self.tshark_path)
        if sys.platform.startswith('win'):
            for env in ('ProgramFiles(x86)', 'ProgramFiles'):
                program_files = os.getenv(env)
                if program_files is not None:
                    possible_paths.append(
                        os.path.join(program_files, 'Wireshark', 'tshark.exe')
                    )
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None

    def process_reg_request(self,ue,packet):
        # add a new entry and use ran_ue_ngap_id as key in dictionary.
        if(packet.nas_5gs_mm_message_type.raw_value == '5c'):
            logger.info("identity response for GUTI attach")
        else:
            logger.info("---!!!---processing Registration request.---!!!---\n")

        if not hasattr(packet, 'nas_5gs_mm_type_id'):
            logger.warning(
                f'mandatory IE type of ID missing in registrationReuqest or identity response.'
                f"gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))} skip this packet!")
            return False
        
        if hasattr(packet, 'e212_mcc') and hasattr(packet, 'e212_mnc'):
            try:
                mcc = '0' * (3 - len(packet.e212_mcc.get_default_value())) + \
                    packet.e212_mcc.get_default_value()
                mnc = '0' * (3 - len(packet.e212_mnc.get_default_value())) + \
                    packet.e212_mnc.get_default_value()
                ue.ue_dict['mcc'] = mcc
                ue.ue_dict['mnc'] = mnc
                ue.ue_dict['snn'] = '5G:mnc' + mnc + '.mcc' + mcc + '.3gppnetwork.org'
            except Exception as e:
                    logger.error(f'error: encountered error with mcc/mnc of '
                                f"gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))} skip handling mcc/mnc!")
                    return False

        # if ID type is SUCI:
        if packet.nas_5gs_mm_type_id == '1':
            if hasattr(packet, 'nas_pdu'):
                # need further coding here, to check whether SUCI or SUPI.
                try:
                    nas_pdu = packet.nas_pdu.raw_value
                    # if it's plain registration request message.
                    if nas_pdu.startswith('7e0041'):
                        id_length = int(nas_pdu[8:12],16)
                        suci:str = nas_pdu[12:12+id_length*2]
                    # elif it's identity response during GUTI attach，security is 0
                    if nas_pdu.startswith('7e005c'):
                        id_length = int(nas_pdu[8:12],16)
                        suci:str = nas_pdu[12:12+id_length*2]
                    # elif it's identity response during GUTI attach.
                    elif nas_pdu.startswith('7e01') and nas_pdu[14:20] == '7e005c':
                        id_length = int(nas_pdu[20:24], 16)
                        suci: str = nas_pdu[24:24 + id_length * 2]
                    elif nas_pdu.startswith('7e02') and nas_pdu[14:20] == '7e005c': #部分UE写的了加密，但是没有真正进行加密
                        id_length = int(nas_pdu[20:24], 16)
                        suci: str = nas_pdu[24:24 + id_length * 2]
                    bcd_supi:str = ''   # BCD string of plain SUPI
                except Exception as e:
                    logger.error("failed to get SUCI content, operation aborted.")
                    logger.error(f"the error info is :{str(e)} line:{sys._getframe().f_lineno}")
                    return False
                # if SUPI is IMSI format:
                if suci[0] =='0':
                    # if suci is not encrypted:
                    if suci[13] == '0':
                        bcd_supi = suci[2:8] + suci[16:]  # BCD string of SUPI, for example:'13001341000021f0'

                    # if suci is encrypted by profile A
                    elif suci[13] == '1':
                        try:
                            if not self.private_key:
                                raise Exception('no private_key found for SUCI deciphering, please input it before deciphering.')
                            imsi_prefix:str = suci[2:8]     #BCD string
                            routing_indicator = suci[8:12]
                            home_network_key_id = suci[14:16]
                            scheme_output = suci[16:106]
                            public_key_ue_bytes = bytes.fromhex(suci[16:80])
                            encrypted_msin:bytes = bytes.fromhex(suci[80:90])
                            mac_tag_from_message = suci[90:]
                            backend = default_backend()
                            # new output would be '01'+imsi_prefix+routing_indicator+'00'+home_network_key_id
                            # +decrypted_msin+padding ff
                            private_key_amf = x25519.X25519PrivateKey.from_private_bytes(self.private_key)  # private_key class
                            public_key_ue = x25519.X25519PublicKey.from_public_bytes(public_key_ue_bytes)  # public_key class
                            shared_secret_key = private_key_amf.exchange(public_key_ue)  # raw binary string.
                            xkdf = X963KDF(
                                algorithm=hashes.SHA256(),
                                length=64,
                                sharedinfo=public_key_ue_bytes,
                                backend=backend
                            )
                            xkdf_output: bytes = xkdf.derive(shared_secret_key)
                            suci_enc_key: bytes = xkdf_output[0:16]
                            suci_icb: bytes = xkdf_output[16:32]
                            suci_mac_key: bytes = xkdf_output[32:]
                            #ue.ue_dict['suci_enc_key'] = suci_enc_key
                            #ue.ue_dict['suci_icb'] = suci_icb
                            #ue.ue_dict['suci_mac_key'] = suci_mac_key
                            # get mac tag from first 8 bytes of the HMAC output.
                            computed_mac_tag:str = HMAC.new(suci_mac_key, encrypted_msin, SHA256).hexdigest()[0:16]
                            if computed_mac_tag == mac_tag_from_message:
                                #first 8 bytes of ICB will be nonce input of AES, and last 8 bytes of ICB will be Initial_value input.
                                crypto = AES.new(suci_enc_key, mode=AES.MODE_CTR, nonce=suci_icb[0:8],initial_value=suci_icb[8:16])
                                plain_msin:bytes = crypto.decrypt(encrypted_msin)
                                # BCD string of SUPI, for example:'13001341000021f0'
                                bcd_supi = imsi_prefix + plain_msin.hex()
                                decrypted_suci:str = suci[0:2]+imsi_prefix+routing_indicator+'00'+\
                                                 home_network_key_id+plain_msin.hex()
                                # to maintain the same lenght as old message, the new SUCI
                                # would be padded by 'ff' until original length is met
                                decrypted_suci =decrypted_suci + (106-len(decrypted_suci))*'f'
                                decrypted_suci_bytes = bytes.fromhex(decrypted_suci)
                                self.buffer = self.buffer.replace(bytes.fromhex(suci), decrypted_suci_bytes)
                            else:
                                raise Exception('found mac tag mismatched.')
                        except Exception as e:
                            logger.error("failed to decrypt SUCI based on profileA, operation aborted.")
                            logger.error(f"the error info is :{str(e)} line:{sys._getframe().f_lineno}")
                            # traceback.print_exc(file=sys.stdout)
                            # traceback.print_stack(file=sys.stdout)
                            return False
                    # if suci is encrypted by profile B
                    elif suci[13] == '2':
                        try:
                            if not self.private_key:
                                raise Exception('no private_key found for SUCI deciphering, please input it before deciphering.')
                            imsi_prefix: str = suci[2:8]  # BCD string
                            routing_indicator = suci[8:12]
                            home_network_key_id = suci[14:16]
                            scheme_output = suci[16:108]
                            public_key_ue_bytes = bytes.fromhex(suci[16:82])
                            encrypted_msin: bytes = bytes.fromhex(suci[82:92])
                            mac_tag_from_message = suci[92:]
                            # new output would be '01'+imsi_prefix+routing_indicator+'00'+home_network_key_id
                            # +decrypted_msin+padding ff
                            backend = default_backend()
                            private_key_amf_int = int(self.private_key.hex(),base=16)
                            private_key_amf = ec.derive_private_key(
                                private_key_amf_int, ec.SECP256R1(), backend)
                            public_key_amf = private_key_amf.public_key()
                            public_key_ue = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(
                                ),public_key_ue_bytes)  # public_key class
                            shared_key = private_key_amf.exchange(
                                ec.ECDH(), public_key_ue)  # raw binary string.
                            xkdf = X963KDF(
                                algorithm=hashes.SHA256(),
                                length=64,
                                sharedinfo=public_key_ue_bytes,
                                backend=backend
                            )
                            xkdf_output: bytes = xkdf.derive(shared_key)
                            suci_enc_key: bytes = xkdf_output[0:16]
                            suci_icb: bytes = xkdf_output[16:32]
                            suci_mac_key: bytes = xkdf_output[32:]
                            # ue.ue_dict['suci_enc_key'] = suci_enc_key
                            # ue.ue_dict['suci_icb'] = suci_icb
                            # ue.ue_dict['suci_mac_key'] = suci_mac_key
                            computed_mac_tag: str = HMAC.new(suci_mac_key, encrypted_msin, SHA256).hexdigest()[0:16]
                            if computed_mac_tag == mac_tag_from_message:
                                #ue.ue_dict['suci_enc_key'] = suci_enc_key
                                #ue.ue_dict['suci_icb'] = suci_icb
                                #ue.ue_dict['suci_mac_key'] = suci_mac_key
                                crypto = AES.new(suci_enc_key, mode=AES.MODE_CTR, nonce=suci_icb[0:8],initial_value=suci_icb[8:16])
                                plain_msin: bytes = crypto.decrypt(encrypted_msin)
                                # BCD string of SUPI, for example:'13001341000021f0'
                                bcd_supi = imsi_prefix + plain_msin.hex()
                                decrypted_suci: str = suci[0:2] + imsi_prefix + routing_indicator + '00' + \
                                                      home_network_key_id + plain_msin.hex()
                                # to maintain the same lenght as old message, the new SUCI
                                # would be padded by 'ff' until original length is met
                                decrypted_suci = decrypted_suci + (108 - len(decrypted_suci)) * 'f'
                                decrypted_suci_bytes = bytes.fromhex(decrypted_suci)
                                self.buffer = self.buffer.replace(bytes.fromhex(suci), decrypted_suci_bytes)
                            else:
                                raise Exception('found mac tag mismatched.')
                        except Exception as e:
                            logger.error("failed to decrypt SUCI, operation aborted.")
                            logger.error(f"the error info is :{str(e)} line:{sys._getframe().f_lineno}")
                            return False
                # if SUPI is NAI format:
                elif suci[0] =='1':
                    pass

                if bcd_supi:
                    if(len(bcd_supi)== 16):
                        supi = bcd_supi[1] + bcd_supi[0] + bcd_supi[3] + bcd_supi[5] + bcd_supi[4] + \
                           bcd_supi[2] + bcd_supi[7] + bcd_supi[6] + bcd_supi[9] + bcd_supi[8] + \
                           bcd_supi[11] + bcd_supi[10] + bcd_supi[13] + bcd_supi[12] + \
                           bcd_supi[15] + bcd_supi[14]
                    elif(len(bcd_supi)== 14):
                        supi = bcd_supi[1] + bcd_supi[0] + bcd_supi[3] + bcd_supi[5] + bcd_supi[4] + \
                           bcd_supi[2] + bcd_supi[7] + bcd_supi[6] + bcd_supi[9] + bcd_supi[8] + \
                           bcd_supi[11] + bcd_supi[10] + bcd_supi[13] + bcd_supi[12]
                    else:
                        logger.warning(
                        f'supi is invalid.'
                        f'bcd_supi:{bcd_supi} skip this packet!')
                        return False
                    supi = supi.replace('f', '')
                    ue.ue_dict['supi'] = supi
                    result,new_ue = self.merge_tempUe_to_Ue(ue)
                    return result,new_ue
        # else if id type is GUTI:
        elif packet.nas_5gs_mm_type_id == '2':
            supi_found,new_ue = self.process_tmsi_id(ue,packet)
            if(supi_found):
                self.set_local_nas_count(new_ue,packet,direction=0)
                self.process_nas_integrity(new_ue,packet,direction=0)
                return True,new_ue
            else:
                return True,ue
        # else if ID type is IMEI:
        elif packet.nas_5gs_mm_type_id == '3':
            pass
        # else if ID type is 5G-S-TMSI:
        elif packet.nas_5gs_mm_type_id == '4':
            pass
        # else if ID type is IMEISV:
        elif packet.nas_5gs_mm_type_id == '5':
            pass
        # no identity
        else:
            return False
        return True

    def process_auth_request(self,ue,packet):
        # future question: how to tell whether it's AKA or EAP-AKA' challenge?
        try:
            # below rand/autn/mac/amf/sqn are all binary strings.
            abba = bytes.fromhex(packet.nas_5gs_mm_abba_contents.raw_value)
            rand = bytes.fromhex(packet.gsm_a_dtap_rand.raw_value)
            autn = bytes.fromhex(packet.gsm_a_dtap_autn.raw_value)
            sqn_xor_ak = bytes.fromhex(packet.gsm_a_dtap_autn_sqn_xor_ak.raw_value)
            amf = bytes.fromhex(packet.gsm_a_dtap_autn_amf.raw_value)
            mac = bytes.fromhex(packet.gsm_a_dtap_autn_mac.raw_value)
            ue.ue_dict['abba'] = abba
            ue.ue_dict['rand'] = rand
            ue.ue_dict['autn'] = autn
            ue.ue_dict['sqn_xor_ak'] = sqn_xor_ak
            ue.ue_dict['amf'] = amf
            ue.ue_dict['mac'] = mac

            if ue.op == None:
                ue.op = self.OP
            if ue.key == None:
                ue.key = self.secret_key

            res, ck, ik = self.call_milenage(ue.key, ue.op, self.OPC,rand, autn, sqn_xor_ak, amf, mac)
            if res is None:
                logger.error(f'error generating res/ck/ik, skip packet : IP identification:,'
                            f"gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))} ")
                return False
            logger.info('compute CK/IK from auth_request message successfully!')


            # get SNN from dict as bytes string.
            snn:bytes = ue.ue_dict['snn'].encode('ascii')
            if not snn :
                logger.warning(f'error getting SNN for this UE, skip packet : IP identification: ,'
                            f"gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))}\n")
                return False
                
            # computing kausf
            kausf_input_string = b'\x6a' + snn + len(snn).to_bytes(2, byteorder='big') \
                           + sqn_xor_ak + len(sqn_xor_ak).to_bytes(2, byteorder='big')
            input_key = ck + ik
            kausf = bytes.fromhex(HMAC.new(input_key, kausf_input_string, SHA256).hexdigest())
            ue.ue_dict['kausf'] = kausf
            # computing kseaf
            kseaf_input_string = b'\x6c' + snn + len(snn).to_bytes(2, byteorder='big')
            input_key = kausf
            kseaf = bytes.fromhex(HMAC.new(input_key, kseaf_input_string, SHA256).hexdigest())
            ue.ue_dict['kseaf'] = kseaf
            logger.info(f"supi:{ue.ue_dict['supi']},tmsi:{ue.nas_5gs_5g_tmsi.hex()},"
                f"compute kseaf based on snn and CK/IK successfully!")
            logger.info(f'\n'
            f'ck:{ck.hex()}\n'
            f'ik:{ik.hex()}\n'
            f'kausf_input_string:{kausf_input_string.hex()}\n' 
            f'kausf:{kausf.hex()}\n'
            f'kseaf_input_string:{kausf_input_string.hex()}\n' 
            f'kseaf:{kseaf.hex()}')

            # get SNN from dict as bytes string.
            '''todo；if 'supi' in ue.ue_dict and ue.ue_dict['supi']!= None:
                supi:bytes = ue.ue_dict['supi'].encode('ascii')
                # computing kamf
                abba = b'\x00\x00'
                kamf_input_string = b'\x6d' + supi + len(supi).to_bytes(2, byteorder='big') + abba + b'\x00\x02'
                input_key = kseaf
                kamf = bytes.fromhex(HMAC.new(input_key, kamf_input_string, SHA256).hexdigest())
                ue.ue_dict['kamf'] = kamf
                logger.info(f"supi:{ue.ue_dict['supi']},tmsi:{ue.nas_5gs_5g_tmsi.hex()},"
                    f'compute Kamf based on supi and CK/IK successfully!\n'
                    f"kamf:{kamf.hex()}")'''
            return True

        except Exception as e:
            logger.error(f'error handling authentication vector ')
            logger.error(f'the error info is :{str(e)} line:{sys._getframe().f_lineno}')
            return False

    def process_securitymode_command(self,ue,packet):
        try:
            # get encryption algorithm from security mode command message.
            encryption_algorithm_id = packet.nas_pdu.raw_value[20]

            # get interity algorithm from security mode command message.
            integrity_algorithm_id = packet.nas_pdu.raw_value[21]

            # algorithm_id ='0' for null encryption, '1' for snow3G, '2' for 'AES', '3' for ZUC
            ue.ue_dict['encryption_algorithm_id'] = encryption_algorithm_id
            ue.ue_dict['integrity_algorithm_id'] = integrity_algorithm_id
            if 'kseaf' not in ue.ue_dict or ue.ue_dict['kseaf']== None:
                logger.info(f'kseaf not generation yet')
                return False

            input_key = ue.ue_dict['kseaf']
            if 'supi' in ue.ue_dict and ue.ue_dict['supi']!= None:
                supi:bytes = ue.ue_dict['supi'].encode('ascii')
                # computing kamf
                abba = b'\x00\x00'
                kamf_input_string = b'\x6d' + supi + len(supi).to_bytes(2, byteorder='big') + abba + b'\x00\x02'
                kamf = bytes.fromhex(HMAC.new(input_key, kamf_input_string, SHA256).hexdigest())
                ue.ue_dict['kamf'] = kamf
                logger.info(f'compute Kamf successfully!')
                logger.info(f"supi:{ue.ue_dict['supi']},kamf:{kamf}")
            else:
                return False
                
            algorithm_type_dist = b'\x01'   #type_id for nas_encryption_key
            input_string = b'\x69' + algorithm_type_dist + b'\x00\x01' + \
                           bytes.fromhex('0'+encryption_algorithm_id) + b'\x00\x01'
            input_key = ue.ue_dict['kamf']
            # cipher_key uses only last 128 bytes of HMAC output, the bytes string would be 32 bytes long
            # so get the last 16 bytes of bytes string only for cipher_key.
            # should add more logic here, add cipher_key only if auth is successful.
            cipher_key = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())[16:]

            algorithm_type_interity_dist = b'\x02'   #type_id for nas interity_key
            input_string = b'\x69' + algorithm_type_interity_dist + b'\x00\x01' + \
                           bytes.fromhex('0'+integrity_algorithm_id) + b'\x00\x01'
            integrity_key = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())[16:]

            ue.ue_dict['cipher_key'] = cipher_key
            ue.ue_dict['integrity_key'] = integrity_key
            logger.info("compute NasEnc and NasInt key successfully!")
            logger.info(f'Nas cipher key:{cipher_key.hex()}\n'
            f'Nas integrity key:{integrity_key.hex()}')

            return True
        except Exception as e:
            logger.error(f'the error info is :{str(e)} line:{sys._getframe().f_lineno}')
            return False

    def process_nas_decipher(self,ue,packet,direction):
        try:
            ran_ue_ngap_id= packet.ran_ue_ngap_id.raw_value

            if 'supi' not in ue.ue_dict or ue.ue_dict['supi']==None:
                return False

            if ('cipher_key' not in ue.ue_dict):
                logger.warning(f'warning: no cipher key available for this UE found,'
                           f'skip packet : ran_ue_ngap_id: {ran_ue_ngap_id},'
                           f"gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))}")
                return False

            if direction == 1:
                count_for_ciphering = ue.ue_dict['local_downlink_nas_count']
            elif direction == 0:
                count_for_ciphering = ue.ue_dict['local_uplink_nas_count']

            # #######deciphering with seq number count_for_ciphering#######
            cipher_key = ue.ue_dict['cipher_key']
            # whole nas pdu including the outer security header and mac
            if hasattr(packet,'nas_pdu'):
                nas_pdu = bytes.fromhex(packet.nas_pdu.raw_value)
            elif hasattr(packet,'pdusessionnas_pdu'):
                nas_pdu = bytes.fromhex(packet.pdusessionnas_pdu.raw_value)
            else:
                raise Exception('no nas_pdu found!')
            # get outer security header and mac+seq.
            outer_header = nas_pdu[0:7]
            # get ciphered payload only.
            ciphered_payload = nas_pdu[7:]
            # initial counter block for AES input  should be :
            # COUNT[0] .. COUNT[31] │ BEARER[0] .. BEARER[4] │ DIRECTION │ 0^26 (i.e. 26 zero bits)
            bearer = self.new_bearer_id  # bearer would be 0 in old spec 33.501 and 1 in new spec.
            first_byte_of_bearer_and_direction = (bearer<<3)|(direction<<2)
            plain_payload = None
            # if AES ciphering:
            # algorithm_id = ue.ue_dict['encryption_algorithm_id']
            if 'encryption_algorithm_id' in ue.ue_dict and ue.ue_dict['encryption_algorithm_id'] == '2' and count_for_ciphering is not None:
                # counter_block for AES should be 16 bytes long binary string.
                counter_block = count_for_ciphering.to_bytes(4,byteorder='big') + \
                                first_byte_of_bearer_and_direction.to_bytes(1,byteorder='big') + \
                                b'\x00\x00\x00' + b'\x00'*8
                crypto = AES.new(cipher_key, mode=AES.MODE_CTR, nonce=counter_block[0:8],initial_value=counter_block[8:16])
                plain_payload = crypto.decrypt(ciphered_payload)
            # elif snow3G algorithm:
            elif ue.ue_dict['encryption_algorithm_id'] == '1' and count_for_ciphering is not None:
                plain_payload = pysnow.snow_f8(cipher_key, count_for_ciphering, bearer,
                                               direction, ciphered_payload, len(ciphered_payload)*8)
            # elif ZUC algorithm:
            elif ue.ue_dict['encryption_algorithm_id'] == '3' and count_for_ciphering is not None:
                plain_payload = pyzuc.zuc_eea3(cipher_key, count_for_ciphering, bearer,
                                               direction, len(ciphered_payload) * 8, ciphered_payload)
            # end if

            if plain_payload and plain_payload.startswith(b'\x7e'):
                self.buffer = self.buffer.replace(nas_pdu,outer_header+plain_payload)
                #If the message is Registration accept, and the newly allocated 5G mobile identity is 5G-GUTI
                if(plain_payload[2] == 0x42 and plain_payload[8] == 0x02):
                    ue.nas_5gs_5g_tmsi = plain_payload[15:19]
                    logger.info(f"supi:{ue.ue_dict['supi']},The updated value of 5g_tmsi:{ue.nas_5gs_5g_tmsi.hex()}, Nas message")
                
                nas_5gs_mm_message_str = nas_5gs_mm_message_dict[plain_payload[2].to_bytes(1,byteorder='big').hex()][0]
                logger.info(f"After decipher nas,supi:{ue.ue_dict['supi']},5g-tmsi:{ue.nas_5gs_5g_tmsi.hex()}, NasMmMsgType:{nas_5gs_mm_message_str},"
                    f"ran_ngap_id: {int(ue.ran_ue_ngap_id,16)},gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))}")
                return True
        except Exception as e:
            logger.error(f'the error info is :{str(e)} line:{sys._getframe().f_lineno}')
            #traceback.print_exc(file=sys.stdout)
            #traceback.print_stack(file=sys.stdout)

        return False

    def set_local_nas_count(self,ue,packet,direction):
        try:
            if not hasattr(packet,'nas_5gs_seq_no'):
                return False

            # get seq in message by converting string of hex value into integer.
            msg_nas_seq_no = int(packet.nas_5gs_seq_no.raw_value,base=16)        # msg_nas_seq_no is integer.
            # if it's downlink tansport packet.
            if direction == 1:
                if 'local_downlink_nas_count' in ue.ue_dict:
                    # local nas count in dict is stored as an integer.
                    local_nas_count = ue.ue_dict['local_downlink_nas_count']
                else:
                    local_nas_count = 0
            # elif it's uplink transport packet.
            else:
                if 'local_uplink_nas_count' in ue.ue_dict:
                    local_nas_count = ue.ue_dict['local_uplink_nas_count']
                else:
                    local_nas_count = 0
            # end if

            # if incoming packet's seq is higher than or same as previous one.
            if msg_nas_seq_no  >= local_nas_count % 256 :
                local_nas_count = (local_nas_count//256)*256 + msg_nas_seq_no 
            # elif incoming packet's seq is smaller than previous one.
            elif msg_nas_seq_no  < local_nas_count % 256 :
                # assume wrap around of seq happens with no more than 10 packets lost.
                if local_nas_count % 256 > 250 and msg_nas_seq_no  < 5:
                    local_nas_count = (local_nas_count//256+1) * 256 + msg_nas_seq_no
                else:
                    local_nas_count = (local_nas_count//256)*256 + msg_nas_seq_no % 256
            # end if

            # save local_nas_count back to dict.
            if direction == 1:
                ue.ue_dict['local_downlink_nas_count'] = local_nas_count
            elif direction == 0:
                ue.ue_dict['local_uplink_nas_count'] = local_nas_count
            # end if
            return True
        except Exception as e:
            logger.error(f'the error info is :{str(e)} line:{sys._getframe().f_lineno}')

        return False

    def process_nas_integrity(self,ue,packet,direction):
        try:
            if 'supi' not in ue.ue_dict or ue.ue_dict['supi']==None:
                return False
            # save local_nas_count back to dict.
            if direction == 1:
                count_for_ciphering = ue.ue_dict['local_downlink_nas_count']
            elif direction == 0:
                count_for_ciphering = ue.ue_dict['local_uplink_nas_count']

            if 'integrity_key' not in ue.ue_dict:
                logger.info(f'check_integrity_nas No integrity key yet')
                return False

            integrity_key = ue.ue_dict['integrity_key']
            # whole nas pdu including the outer security header and mac
            if hasattr(packet,'nas_pdu'):
                nas_pdu = bytes.fromhex(packet.nas_pdu.raw_value)
            elif hasattr(packet,'pdusessionnas_pdu'):
                nas_pdu = bytes.fromhex(packet.pdusessionnas_pdu.raw_value)
            else:
                raise Exception('no nas_pdu found!')
            # get outer security header and mac+seq.
            message_auth_code_pdu = nas_pdu[2:6]

            # get ciphered payload only.
            seq_no_and_ciphered_payload = nas_pdu[6:]
            # initial counter block for AES input  should be :
            # COUNT[0] .. COUNT[31] │ BEARER[0] .. BEARER[4] │ DIRECTION │ 0^26 (i.e. 26 zero bits)
            bearer = self.new_bearer_id  # bearer would be 0 in old spec 33.501 and 1 in new spec.
            first_byte_of_bearer_and_direction = (bearer<<3)|(direction<<2)
            #plain_payload = None
            # if AES ciphering:
            # algorithm_id = ue.ue_dict['encryption_algorithm_id']
            if 'encryption_algorithm_id' in ue.ue_dict and ue.ue_dict['integrity_algorithm_id'] == '2' and count_for_ciphering is not None:
                # counter_block for AES should be 16 bytes long binary string.
                counter_block = count_for_ciphering.to_bytes(4,byteorder='big') + \
                                first_byte_of_bearer_and_direction.to_bytes(1,byteorder='big') + \
                                b'\x00\x00\x00'
                #crypto = AES.new(integrity_key, mode=AES.MODE_CTR, nonce=counter_block[0:8],initial_value=counter_block[8:16])
                #plain_payload = crypto.decrypt(ciphered_payload)
                
                msg=counter_block + seq_no_and_ciphered_payload
                h1 = CMAC.new(integrity_key, ciphermod=AES)
                computed_mac_tag = h1.update(msg)

                message_auth_code_rsp = bytes.fromhex(computed_mac_tag.hexdigest())[0:4]
                #message_auth_code_rsp = computed_mac_tag.hexdigest()[0:8]

                #cmac = CMAC(integrity_key, AES_ECB, Tlen=32)
                #computed_mac_tag = cmac.cmac(msg)

            # elif snow3G algorithm:
            elif ue.ue_dict['integrity_algorithm_id'] == '1' and count_for_ciphering is not None:
                message_auth_code_rsp = pysnow.snow_f8(integrity_key, count_for_ciphering, bearer,
                                               direction, seq_no_and_ciphered_payload, len(seq_no_and_ciphered_payload)*8)
            # elif ZUC algorithm:
            elif ue.ue_dict['integrity_algorithm_id'] == '3' and count_for_ciphering is not None:
                message_auth_code_rsp = pyzuc.zuc_eea3(integrity_key, count_for_ciphering, bearer,
                                               direction, len(seq_no_and_ciphered_payload) * 8, seq_no_and_ciphered_payload)
            # end if

            if message_auth_code_rsp != message_auth_code_pdu:
                logger.warning(f"ran_ngap_id: {int(ue.ran_ue_ngap_id,16)},gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))},"
                    f'message integrity check failed')
            else:
                logger.info(f"ran_ngap_id: {int(ue.ran_ue_ngap_id,16)},gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))},"
                    f'message integrity check success')
            return True
        except Exception as e:
            logger.error(f'the error info is :{str(e)} line:{sys._getframe().f_lineno}')

        return False

    def filter_pcap(self):
        if self.file_location:
            file_name = self.file_location
        else:
            logger.error("critical error: the pcap file doesn't exist!")
            return False
        #
        #    file_name = None
        #    if len(sys.argv) >= 2:
        #        if sys.argv[1]:
        #            file_name = sys.argv[1]
        #    else:
        #        file_name='d:\\5G-ZUC.pcap'
        #

        # check if file exists, if not, exit program,else,define a new file name for filtered pcap file.
        if not os.path.exists(file_name):
            logger.error("critical error: the pcap file doesn't exist!")
            return False

        if not (file_name.upper().endswith('.PCAP') or file_name.upper().endswith('.CAP')):
            logger.error("the input file must be ended with .pcap or .cap!")
            return False

        self.filtered_file_name = file_name.replace('.pcap', '').replace('.PCAP', '').replace('.CAP', '').replace('.cap', '')
        self.filtered_file_name = self.filtered_file_name + '_filtered.pcap'
        # get tshark path and filter source pcap file by ngap
        tshark_path = self.get_tshark_path()
        if tshark_path is None:
            logger.error('fatal error: no tshark.exe from wireshark found in system, make sure you have'
                              'wireshark installed, or manually specify the path of wireshark in GUI')
            return False
        parameters = [tshark_path, '-r', '"'+file_name+'"', '-2', '-R', 'ngap', '-w', '"'+self.filtered_file_name+'"']
        parameters = ' '.join(parameters)
        tshark_process = subprocess.Popen(parameters)
        wait_count = 0
        while True:
            logger.info(f'waiting for pcap filtered by ngap protocol,{wait_count} seconds passed.')
            if wait_count > self.TIME_OUT_FILTER_PCAP:
                logger.error('filter pcap by ngap timed out,please use a smaller pcap '
                                  'instead or filter it by ngap manually before decrypting it!')
                tshark_process.kill()
                return False
            if tshark_process.poll() is not None:
                tshark_process.kill()
                return True
            else:
                module_time_sleep(1)
                wait_count += 1

    def process_tmsi_id(self,ue,packet,service_req = False):
        ue.nas_5gs_5g_tmsi = bytes.fromhex(packet.nas_5gs_5g_tmsi.raw_value)
        #For service request, there is no amf region id
        if hasattr(packet,'nas_5gs_amf_region_id'):
            ue.nas_5gs_amf_id = int(packet.nas_5gs_amf_region_id)<<16|\
                int(packet.nas_5gs_amf_set_id)<<10|\
                int(packet.nas_5gs_amf_pointer)
        else:
            ue.nas_5gs_amf_id = int(packet.nas_5gs_amf_set_id)<<10|\
                int(packet.nas_5gs_amf_pointer)

        supi_found,new_ue = self.merge_tempUe_to_Ue(ue,service_req)
        if(supi_found):
            logger.info(f"supi:{new_ue.ue_dict['supi']},5g-tmsi:{new_ue.nas_5gs_5g_tmsi.hex()}, reg request with GUTI")
            return supi_found, new_ue
        else:
            tmsi_found,old_ue = self.merge_tempUe(ue,service_req)
            if(tmsi_found):
                self.ue_temp_list.remove(old_ue)
            self.ue_temp_list.append(ue)
            return supi_found, ue
         

    def process_service_req(self,ue,packet):
        logger.info("---!!!---processing service request.---!!!---\n")
        ran_ue_ngap_id = ue.ran_ue_ngap_id
        gnb_ip = ue.gnb_ip
        if ('mcc' not in ue.ue_dict) and hasattr(packet, 'e212_5gstai_mcc') and hasattr(packet, 'e212_5gstai_mnc'):
            try:
                mcc = '0' * (3 - len(packet.e212_5gstai_mcc.get_default_value())) + \
                      packet.e212_5gstai_mcc.get_default_value()
                mnc = '0' * (3 - len(packet.e212_5gstai_mnc.get_default_value())) + \
                      packet.e212_5gstai_mnc.get_default_value()
                ue.ue_dict['mcc'] = mcc
                ue.ue_dict['mnc'] = mnc
                ue.ue_dict['snn'] = '5G:mnc' + mnc + '.mcc' + mcc + '.3gppnetwork.org'
            except Exception as e:
                logger.warning(f'error: encountered error with mcc/mnc of '
                               f"ue ngap id:{ran_ue_ngap_id},gnb IP:{socket.inet_ntoa(struct.pack('I',socket.htonl(gnb_ip)))} skip handling mcc/mnc!")
                return False

        if packet.nas_5gs_mm_type_id == '1':     
            pass
        # else if id type is GUTI:
        elif packet.nas_5gs_mm_type_id == '2':
            supi_found,new_ue = self.process_tmsi_id(ue,packet,True)
            if(supi_found):
                self.set_local_nas_count(new_ue,packet,direction=0)
                return True,new_ue
            else:
                return True,ue
        # else if ID type is IMEI:
        elif packet.nas_5gs_mm_type_id == '3':
            pass
        # else if ID type is 5G-S-TMSI:
        elif packet.nas_5gs_mm_type_id == '4':
            supi_found,new_ue = self.process_tmsi_id(ue,packet,True)
            if(supi_found):
                self.set_local_nas_count(new_ue,packet,direction=0)
                return True,new_ue
            else:
                return True,ue
        # else if ID type is IMEISV:
        elif packet.nas_5gs_mm_type_id == '5':
            pass
        # no identity
        else:
            return False
        return True

    def process_supi_invaild(self,ue_temp,packet,direction):
        for ue in self.ue_list:
            supi:bytes = ue.supi
            # computing kamf
            abba = b'\x00\x00'
            kamf_input_string = b'\x6d' + supi + len(supi).to_bytes(2, byteorder='big') + abba + b'\x00\x02'
            input_key = ue_temp.ue_dict['kseaf']
            kamf = bytes.fromhex(HMAC.new(input_key, kamf_input_string, SHA256).hexdigest())
            #ue_temp.ue_dict['kamf'] = kamf

            # get encryption algorithm from security mode command message.
            encryption_algorithm_id = packet.nas_pdu.raw_value[20]

            # get interity algorithm from security mode command message.
            integrity_algorithm_id = packet.nas_pdu.raw_value[21]

            # algorithm_id ='0' for null encryption, '1' for snow3G, '2' for 'AES', '3' for ZUC
            ue.ue_dict['encryption_algorithm_id'] = encryption_algorithm_id
            ue.ue_dict['integrity_algorithm_id'] = integrity_algorithm_id

            algorithm_type_interity_dist = b'\x02'   #type_id for nas interity_key
            input_string = b'\x69' + algorithm_type_interity_dist + b'\x00\x01' + \
                           bytes.fromhex('0'+integrity_algorithm_id) + b'\x00\x01'
            integrity_key = bytes.fromhex(HMAC.new(kamf, input_string, SHA256).hexdigest())[16:]

            # save local_nas_count back to dict.
            msg_nas_seq_no = int(packet.nas_5gs_seq_no.raw_value,base=16)        # msg_nas_seq_no is integer.
            if direction == 1:
                count_for_ciphering = ue.ue_dict['downlink_nas_overflow']*256 + msg_nas_seq_no
            elif direction == 0:
                count_for_ciphering = ue.ue_dict['uplink_nas_overflow']*256 + msg_nas_seq_no

            # whole nas pdu including the outer security header and mac
            if hasattr(packet,'nas_pdu'):
                nas_pdu = bytes.fromhex(packet.nas_pdu.raw_value)
            elif hasattr(packet,'pdusessionnas_pdu'):
                nas_pdu = bytes.fromhex(packet.pdusessionnas_pdu.raw_value)
            else:
                raise Exception('no nas_pdu found!')
            # get outer security header and mac+seq.
            message_auth_code_pdu = nas_pdu[2:6]

            # get ciphered payload only.
            seq_no_and_ciphered_payload = nas_pdu[6:]
            # initial counter block for AES input  should be :
            # COUNT[0] .. COUNT[31] │ BEARER[0] .. BEARER[4] │ DIRECTION │ 0^26 (i.e. 26 zero bits)
            bearer = self.new_bearer_id  # bearer would be 0 in old spec 33.501 and 1 in new spec.
            first_byte_of_bearer_and_direction = (bearer<<3)|(direction<<2)
            #plain_payload = None
            # if AES ciphering:
            # algorithm_id = ue.ue_dict['encryption_algorithm_id']
            if integrity_algorithm_id == '2' and count_for_ciphering is not None:
                # counter_block for AES should be 16 bytes long binary string.
                counter_block = count_for_ciphering.to_bytes(4,byteorder='big') + \
                                first_byte_of_bearer_and_direction.to_bytes(1,byteorder='big') + \
                                b'\x00\x00\x00'
                #crypto = AES.new(integrity_key, mode=AES.MODE_CTR, nonce=counter_block[0:8],initial_value=counter_block[8:16])
                #plain_payload = crypto.decrypt(ciphered_payload)
                
                msg=counter_block + seq_no_and_ciphered_payload
                h1 = CMAC.new(integrity_key, ciphermod=AES)
                computed_mac_tag = h1.update(msg)

                message_auth_code_rsp = bytes.fromhex(computed_mac_tag.hexdigest())[0:4]

            # elif snow3G algorithm:
            elif integrity_algorithm_id == '1' and count_for_ciphering is not None:
                message_auth_code_rsp = pysnow.snow_f8(integrity_key, count_for_ciphering, bearer,
                                               direction, seq_no_and_ciphered_payload, len(seq_no_and_ciphered_payload)*8)
            # elif ZUC algorithm:
            elif integrity_algorithm_id == '3' and count_for_ciphering is not None:
                message_auth_code_rsp = pyzuc.zuc_eea3(integrity_key, count_for_ciphering, bearer,
                                               direction, len(seq_no_and_ciphered_payload) * 8, seq_no_and_ciphered_payload)
            # end if

            if message_auth_code_rsp != message_auth_code_pdu:
                continue
            else:
                self.copy_Ue_from_tempUe(ue,ue_temp)
                logger.info(f"supi:{ue.ue_dict['supi']},tmsi:{ue.nas_5gs_5g_tmsi.hex()}"
                    f'message auth success,Get supi from config file ,message type:{packet.nas_5gs_mm_message_type.raw_value}')
                return True,ue
        return False

    def ue_info_logger(self,ue,packet_layer_ngap,packet_number):
        try:
            nas_5gs_mm_message_type = None
            nas_5gs_mm_message_str = None
            if hasattr(packet_layer_ngap,'nas_5gs_mm_message_type'): 
                nas_5gs_mm_message_type = packet_layer_ngap.nas_5gs_mm_message_type.raw_value
                nas_5gs_mm_message_str = nas_5gs_mm_message_dict[nas_5gs_mm_message_type][0]

            logger.info(f'--- packet {packet_number} processing. ---')
            logger.info(f"supi:{ue.ue_dict['supi']},5g-tmsi:{ue.nas_5gs_5g_tmsi.hex()}, NasMmMsgType:{nas_5gs_mm_message_str},"
                f"ran_ngap_id: {int(ue.ran_ue_ngap_id,16)},gnb ip:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(ue.gnb_ip,16))))}")
        except Exception as e:
            logger.warning(f'handling ue_info_logger, the error info is :{str(e)} line:{sys._getframe().f_lineno}')
        return

    def process_nas_security(self,ue,packet_layer_ngap,direction):
        try:
            if not (('snn' in ue.ue_dict) and ('supi' in ue.ue_dict)):
                logger.info(
                    f'no UE with supi record found in normal dict, skip this packet!')
                return False

            security_header_type = packet_layer_ngap.nas_5gs_security_header_type.raw_value

            nas_5gs_mm_message_type = None
            if hasattr(packet_layer_ngap, 'nas_5gs_mm_message_type'):
                # if packet is authentication request,get rand,autn,abba,SQN,AK,MAC from message.
                nas_5gs_mm_message_type =  packet_layer_ngap.nas_5gs_mm_message_type.raw_value

            # if it's plain nas message:
            if security_header_type == '0':
                # if wireshark dissection for null encryption is enabled:
                if nas_5gs_mm_message_type == '56':
                    self.process_auth_request(ue,packet_layer_ngap)
                logger.info(f'skip plain nas message packet.')
            # if it's plain nas message but integrity enabled.
            elif security_header_type == '1' or security_header_type == '3':
                if nas_5gs_mm_message_type == '5d':
                    # get the algorithm type, then compute KDF_ALGKEY. if algkey is 128 bits,
                    # use the last 128 bits of 256 bits long algkey.
                    if 'supi' in ue.ue_dict and ue.ue_dict['supi']!=None:
                        self.process_securitymode_command(ue,packet_layer_ngap)
                    else:
                        result,ue = self.process_supi_invaild(ue,packet_layer_ngap,direction)
                        if(result):
                            #process_supi_invaild function just verify the supi context, no real copy
                            self.process_securitymode_command(ue,packet_layer_ngap)
                self.process_nas_integrity(ue,packet_layer_ngap, direction)
            # elif it's ciphered and integrityed nas message.
            elif security_header_type == '2' or security_header_type == '4':
                # if packet is authentication request,get rand,autn,abba,SQN,AK,MAC from message.
                if nas_5gs_mm_message_type == '56':
                    #The authentication message itself is no longer decrypted and sanitized
                    self.process_auth_request(ue,packet_layer_ngap)

                self.process_nas_integrity(ue,packet_layer_ngap, direction)
                # if null encryption, do nothing but continue for next packet.
                if 'encryption_algorithm_id' in ue.ue_dict and ue.ue_dict['encryption_algorithm_id'] == '0':
                    logger.info(f'skip deciphering packet due to null encryption algorithm.')
                    return False
                # otherwise, decipher packet.
                if self.process_nas_decipher(ue,packet_layer_ngap,direction):
                    logger.info(f'deciphering packet successfully!')
                else:
                    logger.error(f'deciphering packet failed')
                # end if
                return False
        except Exception as e:
            logger.error('failed to handle security nas message.')
            logger.error(f'the error info is :{str(e)} line:{sys._getframe().f_lineno}')
            return False

    def process_nas_message(self,packet,packet_layer_ngap,packet_number):
        try:
            ran_ue_ngap_id = packet_layer_ngap.ran_ue_ngap_id.raw_value
        except Exception as e:
            logger.warning(
                f'error: error handling ran_ue_ngap_id in {packet_number}, skip this packet!')
            return True

        # if procedurecode is "initialUEmessage"(0x0f),create new UE item in dictionary:
        if packet_layer_ngap.procedurecode.raw_value == '0f':
            # skip this packet if initialUEmessage has no nas_5gs_mm_message_type, note only plain nas
            # has this parameter.
            try:
                gnb_ip = packet.ip.src.raw_value
                amf_ip = packet.ip.dst.raw_value
            except Exception as e:
                logger.warning(
                    f'error: error handling source/dest IP in {packet_number}, skip this packet!')
                return False
            if not hasattr(packet_layer_ngap,'nas_5gs_mm_message_type'):
                logger.warning(f'error: one or more mandatory IE in packet {packet_number} is missing, skip this packet!')
                return False
            if amf_ip and (amf_ip not in self.amf_ip_list):
                self.amf_ip_list.append(amf_ip)

            #By default, ue info  is not added to ue_temp_list.
            ue = self.create_temp_ue(gnb_ip,ran_ue_ngap_id,amf_ip)

            # if message type is "registration request".
            if packet_layer_ngap.nas_5gs_mm_message_type.raw_value == '41':
                result,ue = self.process_reg_request(ue,packet_layer_ngap)

            # elif message type is "service request"
            elif packet_layer_ngap.nas_5gs_mm_message_type.raw_value == '4c':
                # need further coding here.
                result,ue = self.process_service_req(ue,packet_layer_ngap)
            
            if(result):
                self.ue_info_logger(ue,packet_layer_ngap,packet_number)
                self.process_nas_security(ue,packet_layer_ngap,0)
         
        # elif DownlinkNASTransport message.
        elif packet_layer_ngap.procedurecode.raw_value == '04' and packet.ip.src.raw_value in self.amf_ip_list:
            try:
                gnb_ip = packet.ip.dst.raw_value
                amf_ip = packet.ip.src.raw_value
            except Exception as e:
                logger.warning(
                    f'error: error handling src/dst IP in {packet_number}, skip this packet!')
                return False

            if amf_ip and (amf_ip not in self.amf_ip_list):
                self.amf_ip_list.append(amf_ip)

            direction = 1

            # check if UE record in self.ue_dict had already been added.
            # if not, skip this packet.
            result,ue = self.get_ue_for_ngap(gnb_ip,ran_ue_ngap_id)
            if result == False:
                result,ue = self.get_temp_ue_for_ngap(gnb_ip,ran_ue_ngap_id)
                if result == False:
                    logger.warning(f'warning: no  available for this UE found,'
                                f"DownlinkNASTransport skip packet, ran_ue_ngap_id: {int(ran_ue_ngap_id,16)},gnb IP:{socket.inet_ntoa(struct.pack('I',socket.htonl(int(gnb_ip,16))))}")
                    return False

            # direction parameter for ciphering input, 0 for uplink and 1 for downlink.
            if hasattr(packet_layer_ngap,'nas_5gs_5g_tmsi'):
                ue.nas_5gs_5g_tmsi = bytes.fromhex(packet_layer_ngap.nas_5gs_5g_tmsi.raw_value)
                ue.nas_5gs_amf_id = int(packet_layer_ngap.nas_5gs_amf_region_id)<<16|\
                    int(packet_layer_ngap.nas_5gs_amf_set_id)<<10|\
                    int(packet_layer_ngap.nas_5gs_amf_pointer)
            
            self.ue_info_logger(ue,packet_layer_ngap,packet_number)
            self.set_local_nas_count(ue,packet_layer_ngap,direction)
            self.process_nas_security(ue,packet_layer_ngap,direction)

        # elif UPlinkNASTransport message.
        elif packet_layer_ngap.procedurecode.raw_value == '2e' and packet.ip.dst.raw_value in self.amf_ip_list:
            try:
                gnb_ip = packet.ip.src.raw_value
                amf_ip = packet.ip.dst.raw_value
            except Exception as e:
                logger.warning(
                    f'error: error handling src/dst IP in {packet_number}, skip this packet!')
                return False

            result,ue = self.get_ue_for_ngap(gnb_ip,ran_ue_ngap_id)
            if result == False:
                result,ue = self.get_temp_ue_for_ngap(gnb_ip,ran_ue_ngap_id)
                if result == False:
                    logger.error(f'finding matched UE record in dictionary'
                    f' for packet#{packet_number}, skip this packet!')
                    return False
                    
            direction = 0
            self.set_local_nas_count(ue,packet_layer_ngap,direction)

            self.ue_info_logger(ue,packet_layer_ngap,packet_number)

            # if packet is "identity response for GUTI attach", handle it on priority before other handling.
            if hasattr(packet_layer_ngap,'nas_5gs_mm_message_type') and \
                    packet_layer_ngap.nas_5gs_mm_message_type.raw_value == '5c':
                #todo return self.process_reg_request(ue,packet_layer_ngap)
                self.process_reg_request(ue,packet_layer_ngap)

            return self.process_nas_security(ue,packet_layer_ngap,direction)
            
        elif ((packet_layer_ngap.procedurecode.raw_value == '0e'#InitialContextSetupRequest
            or packet_layer_ngap.procedurecode.raw_value == '1d') #PDUSessionResourceSetupRequest
            and (packet.ip.src.raw_value in self.amf_ip_list)):
            try:
                gnb_ip = packet.ip.dst.raw_value
                amf_ip = packet.ip.src.raw_value
            except Exception as e:
                logger.warning(
                    f'error: error handling src/dst IP in {packet_number}, skip this packet!')
                return False
            # check if UE record in self.ue_dict had already been added.
            # if not, skip this packet.

            result,ue = self.get_ue_for_ngap(gnb_ip,ran_ue_ngap_id)
            if result == False:
                logger.warning(f'error: error finding matched UE record in dictionary'
                f' for packet#{packet_number}, skip this packet!')
                return False

            # direction parameter for ciphering input, 0 for uplink and 1 for downlink.
            direction = 1
            self.set_local_nas_count(ue,packet_layer_ngap,direction)
            self.ue_info_logger(ue,packet_layer_ngap,packet_number)

            if hasattr(packet_layer_ngap,'nas_5gs_5g_tmsi'):
                ue.nas_5gs_5g_tmsi = bytes.fromhex(packet_layer_ngap.nas_5gs_5g_tmsi.raw_value)
                ue.nas_5gs_amf_id = int(packet_layer_ngap.nas_5gs_amf_region_id)<<16|\
                    int(packet_layer_ngap.nas_5gs_amf_set_id)<<10|\
                    int(packet_layer_ngap.nas_5gs_amf_pointer)

            self.process_nas_security(ue,packet_layer_ngap,direction)
        else:
            logger.error(f'packet {packet_number} not belongs to any of initialUE/uplinktransport/dlinktransport '
                         f'skipped this packet!')
            return False

    def get_configfile(self):
        path = os.getcwd() + "\\3GPP_Security.ini"
        cp = configparser.ConfigParser()
        try:
            cp.read(path,encoding="utf-8")
            for section in cp.sections():
                ue = Ue()
                for item in cp.items(section):
                    ue.ue_dict[item[0]] = item[1]
                ue.read_config_Info()
                self.ue_list.append(ue)
        except Exception as e:
            print(f'configfile error,e {str(e)}')

        return 

    def main_function(self):
        if self.filter_pcap():
            logger.info("filter pcap by ngap protocol finished, now start dectypting!\n")
        else:
            logger.error('error filtering pcap by ngap protocol, operation aborted!')
            return False

        # check if filtered_file_name generated by tshark successfully.
        if not os.path.exists(self.filtered_file_name):
            logger.error(f'error: the file {self.filtered_file_name} seems not generated successfuly,operation aborted!')
            return False
        # real all contents inside filtered_file_name into buffer.
        with open(self.filtered_file_name, "rb") as file:
            self.buffer = file.read()

        self.tshark_path = self.get_tshark_path()
        # start reading packet in file by call tshark process.
        # to be done: need to make sure the option "try to decode EEA0" is enabled before launch tshark process.
        if self.tshark_path:
            self.capture = pyshark.FileCapture(self.filtered_file_name, display_filter='nas-5gs',tshark_path=self.tshark_path)
        else:
            self.capture = pyshark.FileCapture(self.filtered_file_name, display_filter='nas-5gs')
        # if the wireshark was not enabled with "try to decode EEA0" option, the output of tshark would not
        # have message type value in some message like securityMode command/complete, need to figure out a
        # way how to enable that option in wireshark automatically before running tshark.

        self.get_configfile()

        packet_number = 0
        for packet in self.capture:
            packet_layer_number = 0
            packet_number += 1
            for packet_layer in packet.layers:
                if (hasattr(packet,'ip') and hasattr(packet.ip,'src') and hasattr(packet.ip,'dst')
                and hasattr(packet,'ngap') and hasattr(packet_layer,'ran_ue_ngap_id')
                and (hasattr(packet_layer,'nas_pdu') or hasattr(packet_layer,'pdusessionnas_pdu'))
                and hasattr(packet_layer,'procedurecode')
                and hasattr(packet_layer,'nas_5gs_security_header_type')):
                    packet_layer_number += 1
                    self.process_nas_message(packet,packet_layer,packet_number)
        # end of for loop
        # write deciphered buffer back to pcap file.
        try:
            with open(self.filtered_file_name, "wb") as file:
                file.write(self.buffer)
            logger.info(f'file {self.filtered_file_name} with deciphered content created!')
            del self.buffer,self.amf_ip_list
            return True
        except Exception as e:
            logger.error("error happened during writing decrypted content into pcap, operation aborted!")
            logger.debug(f"the error info is : {str(e)} line:{sys._getframe().f_lineno}")
            return False
            
            

# #################################################################
# **********************start GUI part here************************
# #################################################################
class GuiPart:
    def __init__(self, master, _queue, end_command,start_decrypting):
        self.queue = _queue
        # Set up the GUI
        # master is a main window
        master.geometry("860x550")
        master.title("3GPP NAS deciphering, integrity check and key generation tool")

        self.var_decrypt_suci = tkinter.IntVar()
        self.check_button = tkinter.Checkbutton(master, text="decrypt SUCI:", command=self.checkbutton_check,
                                                variable=self.var_decrypt_suci)
        self.check_button.grid(row=0, sticky=tkinter.E)
        tkinter.Label(master, text="input hex value only in below box(32 bytes),", fg="blue").grid(row=0, column=1, sticky=tkinter.E)
        tkinter.Label(master, text="for example: 0a0b0c0d0e1111..................", fg="blue").grid(row=0, column=2, sticky=tkinter.W)
        tkinter.Label(master, text="private_key_network:").grid(row=1, column=0, sticky=tkinter.E)
        self.entry_private_key = tkinter.Entry(master, state=tkinter.DISABLED, width=34)
        self.entry_private_key.grid(row=1, column=1, sticky=tkinter.W)
        tkinter.Label(master, text="authentication parameters(5G AKA only):").grid(row=2, column=0, sticky=tkinter.E)
        tkinter.Label(master, text="input hex value only in below box(16 bytes),", fg="blue").grid(row=2, column=1, sticky=tkinter.E)
        tkinter.Label(master, text="for example: ac1b030405060708090a0b0c0d0e1111", fg="blue").grid(row=2, column=2, sticky=tkinter.W)
        tkinter.Label(master, text="secret Key of UE:").grid(row=3, column=0, sticky=tkinter.E)
        self.entry_secret_key = tkinter.Entry(master, width=34)
        self.entry_secret_key.grid(row=3, column=1, sticky=tkinter.W)
        self.entry_secret_key.insert(0, r'5122250214c33e723a5dd523fc145fc0')
        self.var_use_op = tkinter.IntVar()
        self.radio_button_op = tkinter.Radiobutton(master, text="use OP", variable=self.var_use_op, value=1,
                                              command=self.radio_button_op_event_handle)
        self.radio_button_op.grid(row=4, column=0, sticky=tkinter.E)
        self.radio_button_opc = tkinter.Radiobutton(master, text="use OPc", variable=self.var_use_op, value=2,
                                               command=self.radio_button_op_event_handle)
        self.radio_button_opc.grid(row=4, column=1, sticky=tkinter.W)
        tkinter.Label(master, text="OP value:").grid(row=6, column=0, sticky=tkinter.E)
        self.entry_op = tkinter.Entry(master, state=tkinter.NORMAL, width=34)
        self.entry_op.grid(row=6, column=1, sticky=tkinter.W)
        self.entry_op.insert(0, r'c9e8763286b5b9ffbdf56e1297d0887b')
        tkinter.Label(master, text="OPc value:").grid(row=7, column=0, sticky=tkinter.E)
        self.entry_opc = tkinter.Entry(master, state=tkinter.DISABLED, width=34)
        self.entry_opc.grid(row=7, column=1, sticky=tkinter.W)
        # attention: need to select this radio button by invoke() after declaration of entry_op
        # otherwise you will get error "entry_op" not defined.
        self.radio_button_op.invoke()
        self.var_new_bearer_id= tkinter.IntVar()
        self.radio_button_bearer_id = tkinter.Radiobutton(master,
                                                        text="bearer ID old spec 33.501",
                                                        variable=self.var_new_bearer_id, value=0)
        self.radio_button_bearer_id.grid(row=8, column=0, sticky=tkinter.E)
        self.radio_button_bearer_id_2 = tkinter.Radiobutton(master,
                                                          text="bearer ID new spec",
                                                          variable=self.var_new_bearer_id, value=1)
        self.radio_button_bearer_id_2.grid(row=8, column=1, sticky=tkinter.W)
        self.radio_button_bearer_id_2.invoke()
        tkinter.Label(master, text="the location of pcap file:").grid(row=10, column=0, sticky=tkinter.E)
        self.entry_pcap = tkinter.Entry(master, width=34)
        self.entry_pcap.grid(row=9, column=1, sticky=tkinter.W)
        #self.entry_pcap.insert(0,'d:/5G-AES.pcap')
        tkinter.Button(master, text='    browse    ', command=self.locate_pcap).grid(row=9, column=2, sticky=tkinter.W)
        self.var_specify_wireshark_path = tkinter.IntVar()
        self.check_button_wireshark = tkinter.Checkbutton(master,
                                    text="specify_tshark_path(uncheck it for auto detect):",
                                                          command=self.checkbutton_wireshark_check,
                                                variable=self.var_specify_wireshark_path)
        self.check_button_wireshark.grid(row=10, sticky=tkinter.E)
        self.entry_wireshark = tkinter.Entry(master, width=34)
        self.entry_wireshark.grid(row=10, column=1, sticky=tkinter.W)
        self.entry_wireshark.configure(state='disabled')
        tkinter.Button(master, text='    browse    ', command=self.locate_tshark).grid(row=10, column=2, sticky=tkinter.W)

        tkinter.Button(master, text='Start decryption and integrity check pcap', command=start_decrypting).grid(row=11, column=1, sticky=tkinter.W)
        tkinter.Button(master, text='        Exit       ', command=end_command).grid(row=11, column=2, sticky=tkinter.W)
        self.scrollbar = tkinter.Scrollbar(master)
        self.scrollbar.grid(row=12, column=3, columnspan=14, sticky=tkinter.NS)
        self.list_box = tkinter.Text(master, height=14, width=120, wrap=tkinter.WORD,yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.list_box.yview)
        self.list_box.grid(row=12, column=0, columnspan=3, sticky=tkinter.W)
        self.list_box.insert(tkinter.END, 'real time log:')
        tkinter.Label(master, text=" ").grid(row=15, column=2, sticky=tkinter.E)
        tkinter.Label(master, text="By J.T -2020 and huiwu2068").grid(row=16, column=2, sticky=tkinter.E)
        master.protocol("WM_DELETE_WINDOW", end_command)

    def checkbutton_check(self):
        if self.var_decrypt_suci.get() == 1:
            self.entry_private_key.configure(state='normal')
        elif self.var_decrypt_suci.get() == 0:
            self.entry_private_key.configure(state='disabled')

    def checkbutton_wireshark_check(self):
        if self.var_specify_wireshark_path.get() == 1:
            self.entry_wireshark.configure(state='normal')
            self.entry_wireshark.insert(0, r'D:\Program Files\Wireshark\tshark.exe')
        elif self.var_specify_wireshark_path.get() == 0:
            self.entry_wireshark.configure(state='disabled')

    def radio_button_op_event_handle(self):
        if self.var_use_op.get() == 1:
            self.entry_op.configure(state='normal')
            self.entry_opc.configure(state='disabled')
        elif self.var_use_op.get() == 2:
            self.entry_opc.configure(state='normal')
            self.entry_op.configure(state='disabled')

    def locate_pcap(self):
        filename = askopenfilename()  # show an "Open" dialog box and return the path to the selected file
        self.entry_pcap.delete(0, tkinter.END)
        self.entry_pcap.insert(0, filename)

    def locate_tshark(self):
        filename = askopenfilename()  # show an "Open" dialog box and return the path to the selected file
        self.entry_wireshark.delete(0, tkinter.END)
        self.entry_wireshark.insert(0, filename)

    def process_incoming(self):
        """Handle all messages currently in the queue, if any."""
        while self.queue.qsize():
            try:
                msg = self.queue.get(0)
                # Check contents of message and do whatever is needed.
                if msg:
                    if isinstance(msg,str):
                        self.list_box.insert(tkinter.END, msg+'\n')
                        self.list_box.yview(tkinter.END)
                    elif isinstance(msg,logging.LogRecord):
                        self.list_box.insert(tkinter.END, msg.getMessage()+'\n')
                        self.list_box.yview(tkinter.END)

            except queue.Empty:
                # just on general principles, although we don't
                # expect this branch to be taken in this case
                pass

    def get_gui_input(self):
        try:
            decrypt_suci, private_key, secret_key, use_op, op, opc, file_location, tshark_path,new_bearer_id=None,\
                                                None,None,None,None,None,None,None,None
            decrypt_suci = self.var_decrypt_suci.get()
            if decrypt_suci and decrypt_suci==1:
                private_key = bytes.fromhex(self.entry_private_key.get())
                if not (private_key and len(private_key)==32):
                    raise Exception('private key error!')
            elif not isinstance(decrypt_suci,int):
                raise Exception("SUCI checkbox error!")

            new_bearer_id = self.var_new_bearer_id.get()
            if isinstance(new_bearer_id, int) and (new_bearer_id == 0 or new_bearer_id == 1):
                pass
            else:
                raise Exception("new_bearer_ID value error!")

            specify_wireshark_path = self.var_specify_wireshark_path.get()
            if specify_wireshark_path and specify_wireshark_path==1:
                tshark_path = self.entry_wireshark.get()
                if not tshark_path:
                    raise Exception('tshark path error!')
            elif not isinstance(specify_wireshark_path,int):
                raise Exception("tshark checkbox error!")

            secret_key = bytes.fromhex(self.entry_secret_key.get())
            if not (secret_key and len(secret_key)==16):
                raise Exception('secret key error!')

            use_op = self.var_use_op.get()
            if not (use_op and (use_op==1 or use_op==2)):
                raise Exception('radio button of use op/opc error!')
            elif use_op == 1:
                op = bytes.fromhex(self.entry_op.get())
                if not (op and len(op)==16):
                    raise Exception('op value error!')
            elif use_op == 2:
                opc = bytes.fromhex(self.entry_opc.get())
                if not (opc and len(opc)==16):
                    raise Exception('opc error!')

            file_location = self.entry_pcap.get()
            if not (file_location and isinstance(file_location,str)):
                raise Exception('file name error!')

            logger.debug(f"GUI input is : {decrypt_suci, private_key, secret_key, use_op, op, opc, file_location,tshark_path}")
            return decrypt_suci, private_key, secret_key, use_op, op, opc, file_location,tshark_path,new_bearer_id
        except Exception as e:
            logger.error("error: one or more mandatory parameter input incorrect, please try again!")
            logger.error(f'the error info is:{str(e)} line:{sys._getframe().f_lineno}')
            return None, None, None, None, None, None, None


class ThreadedClient:
    """
    Launch the main part of the GUI and the decrypting thread. periodicCall and
    endApplication could reside in the GUI part, but putting them here
    means that you have all the thread controls in a single place.
    """
    def __init__(self, main_window):
        """
        Start the GUI and the asynchronous threads. We are in the main
        (original) thread of the application, which will later be used by
        the GUI as well. We spawn a new thread for decrypting.
        """
        self.master = main_window

        # Create the queue
        self.queue = queue.Queue()
        # decryption object will be instantiated later by start_decrypting function.
        self.decryption_and_integrity_check = None
        # Set up the GUI part
        self.gui = GuiPart(main_window, self.queue, self.end_application, self.start_decryption_and_integrity_check)
        self.running = 1
        self.thread1 = None
        # Start the periodic call in the GUI to check if the queue contains
        # anything
        self.LOGFILE = "decipher" + str(datetime.now()).replace(":", "-").replace(" ", "-") + ".log"
        level = logging.INFO
        self.init_log(level)
        self.periodic_call()

    def init_log(self,log_level=logging.INFO):
        try:
            # create logger
            logger.propagate = False
            logger.setLevel(log_level)

            # create file handler, with a formatter and set level to info
            ch = logging.handlers.RotatingFileHandler(self.LOGFILE,
                                                      mode='a', maxBytes=10000000, backupCount=5)
            # need to check whether failed with creating lscheck.log here.
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            ch.setLevel(log_level)
            logger.addHandler(ch)
            # create one more handler for output to stdout.
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(log_level)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            # add queue handler into logger so that any log message would be recorded into thread queue as well.
            # GUI part would read the queue periodically and print it into GUI window.
            if self.queue:
                logger.debug(f"queue handler: {self.queue}")
                queue_handler = QueueHandler(self.queue)
                queue_handler.setFormatter(formatter)
                queue_handler.setLevel(log_level)
                logger.addHandler(queue_handler)
                logger.debug("success with add queue handler.")

            logger.debug("log file is generated by file name:"+self.LOGFILE)
            return logger
        except Exception as e:
            print("initialize a new log file and writing into it failure,"
                  " make sure your current account has write privilege to current directory!")
            logger.error("error: " + str(e)+'')
            return logger

    def periodic_call(self):
        """
        Check every 200 ms if there is something new in the queue.
        """
        self.gui.process_incoming()
        if not self.running:
            # do some cleanup before  shutting it down.
            del self.gui,self.decryption_and_integrity_check
            sys.exit(1)
        self.master.after(200, self.periodic_call)

    def start_decryption_and_integrity_check(self):
        # Set up the thread to do decrypting.
        decrypt_suci, private_key, secret_key, use_op, op, opc, file_location, tshark_path,new_bearer_id = self.gui.get_gui_input()
        if secret_key is None or file_location is None:
            logger.error("get input failed, abort decryption!")
            return False

        self.decryption_and_integrity_check = Decryption(decrypt_suci, private_key, secret_key, use_op, op,
                                     opc, file_location,self.queue,tshark_path,new_bearer_id)
        self.decryption_and_integrity_check_thread = threading.Thread(target=self.decryption_and_integrity_check.main_function)
        self.decryption_and_integrity_check_thread.start()

    def end_application(self):
        self.running = 0
        module_time_sleep(0.2)
        del self.gui,self.decryption_and_integrity_check
        print("closing")
        sys.exit(1)


main_window = tkinter.Tk()
client = ThreadedClient(main_window)
main_window.mainloop()


