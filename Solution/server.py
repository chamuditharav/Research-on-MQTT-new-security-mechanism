import paho.mqtt.client as mqtt
from threading import Thread
from time import sleep
import json
import rsa


def generateKeys(ksize=1024):
    (publicKey, privateKey) = rsa.newkeys(ksize)
    return publicKey, privateKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        print("Decryption Error")
        #return "Coudn't decrypt"


class MQTTS_SERVER(Thread):
    server_id = ""
    server = None
    server_ip = ""
    server_port = 0
    server_stream = ""
    clients = []


    
    def __init__(self, serverID, server_ip, server_port, client_list):
      self.server_id = serverID
      self.server_ip = server_ip
      self.server_port = server_port
      self.server_stream = f"{server_ip}/tx"
      self.clients = client_list


      try:
        sleep(3)
        self.server = mqtt.Client()
        self.server.connect(self.server_ip,self.server_port)
        self.server.on_connect = self.server_init
        self.server.on_message = self.on_message
        self.server.subscribe(self.server_stream)
      except:
        print("Connection faild!")
        self.server.loop_stop()



    def validate(self):
        pass
    

    def key_ex(self,dataFrame):
        if(dataFrame.split(":")[2] != ""):
            try:
                key_format = bytes.fromhex(dataFrame.split(":")[2])
                
                key = rsa.PublicKey.load_pkcs1(key_format)
                
                self.clients[dataFrame.split(":")[1]][1] = key
                svPub, svPri = generateKeys()
                self.clients[dataFrame.split(":")[1]][2] = svPri
                svPubKhex = svPub._save_pkcs1_pem().hex()
                sleep(2)
                print("transmitting sv pub k")
                self.server.publish(f'{dataFrame.split(":")[1]}/rx',f"SVR-KEY_EXCHANGE_REPLY:{svPubKhex}")
                self.clients[dataFrame.split(":")[1]][3] = 0
                print("Key exhanged !")
            except:
                print("Key exchange faild")
    
    def rolling_key_ex(self,dataFrame):
        try:
            src_name = dataFrame.split(":")[1]
            unenc_dataFrame = decrypt(bytes.fromhex(dataFrame.split(":")[2]), self.clients[src_name][2])
            self.clients[src_name][3] = int(unenc_dataFrame.split(":")[0])
            self.clients[src_name][4] = int(unenc_dataFrame.split(":")[1])
            self.clients[src_name][5] = int(unenc_dataFrame.split(":")[2])
            self.server.publish(f'{src_name}/rx',f"SVR-ROLL-SUCC")
            print("Rolling key exchnage successfull")
        except:
            self.server.publish(f'{src_name}/rx',f"SVR-ROLL-FAIL")
            self.clients[src_name][3] = 0
            self.clients[src_name][4] = 1
            self.clients[src_name][5] = 100
            print("Rolling key exchnage faild")


    def on_message(self,server, userdata, msg):
        dataFrame = str(msg.payload.decode())
        if(dataFrame.split(":")[0] == "KEY_EXCHANGE_REQUEST"):
            key_ex = Thread(target=self.key_ex, args=(dataFrame,))
            key_ex.start()
        
        elif(dataFrame.split(":")[0] == "INIT-ROLL"):
            rolling_key_ex_thread = Thread(target=self.rolling_key_ex , args=(dataFrame,))
            rolling_key_ex_thread.start()          


        elif(dataFrame.split(":")[0] == "UNENC"): #receiving unencrypted msg
            try:
                src_name = dataFrame.split(":")[2]
                dst_ip = dataFrame.split(":")[3]
                unenc_msg = dataFrame.split(":")[4]
                if(dataFrame.split(":")[1] == self.clients[src_name][0]):
                    unenc_data_handle_thread = Thread(target=self.sendUnencMSG , args=(src_name, dst_ip, unenc_msg,))
                    unenc_data_handle_thread.start()
                else:
                    print("UNENC - Client Error!")
            except:
                print("UNENC - Courroupted data recieved")
        
        elif(dataFrame.split(":")[0] == "ENC"):     #clientdataFrame(clientID, pubKey, pvtKey, rollStart, rollStep, rollEnd)
            try:
                src_name = dataFrame.split(":")[1]
                unecn_msg = decrypt(bytes.fromhex(dataFrame.split(":")[2]), self.clients[src_name][2]) #decrypting the msg
                unenc_count = int(decrypt(bytes.fromhex(dataFrame.split(":")[3]), self.clients[src_name][2])) #decrypting the rolling code

                if(self.clients[src_name][0] == unecn_msg.split(":")[0]):
                    if(unenc_count == self.clients[src_name][3]):
                        #print(self.clients[src_name][0] , unecn_msg.split(":")[0])
                        self.sendEncMSG(src_name, unecn_msg.split(":")[2],unecn_msg.split(":")[3])
                        if(self.clients[src_name][3] >= self.clients[src_name][5]):self.clients[src_name][3] = 0
                        else: self.clients[src_name][3] += self.clients[src_name][4]
                    else:
                        print(f"{src_name}:Count error --> Emitting SVR-ROLL-RST")
                        self.server.publish(f'{src_name}/rx',"SVR-ROLL-RST") #sending reset code to client if rolling code is not matching
                else:
                    print("Unauthorized client")
            except:
                print("ENC - Courroupted data recieved or Client error")



    def sendMSG(self,msg):  #MQTTS legacy method
      self.server.publish(self.broker_tx,f"{msg}")


    def sendUnencMSG(self, src, dest, msg):
        dataFrame = f"UNENC-SVR-MSG-HAND:{src}:{msg}"
        self.server.publish(f'{dest}/rx',dataFrame)
        print(f"UNENC Fowarding : {src} -> {dest} : {dataFrame}")

    def sendEncMSG(self, src, dest, msg):
        if(self.clients[dest][1] != ""):
            dataFrame = f"ENC-SVR-MSG-HAND"
            enc_part = encrypt(f"{src}:{msg}", self.clients[dest][1]).hex()
            self.server.publish(f'{dest}/rx',f"{dataFrame}:{enc_part}")
            print(f"ENC Fowarding : {src} -> {dest} : ENC_DATA")
        else:
            print("Cannot pass the data without a key exchange")


    def loop(self):
      self.server.loop_forever()

    def server_init(self,a,b,c,d):
        for client in self.clients.keys():
            print(f"Broadcasting : {client}")
            self.server.publish(f'{client}/rx',f"SVR-INIT")
        print("Server started........")



def format_clients(client_file):
    formatted_clients = {}
    with open(client_file) as json_file:
        data = json.load(json_file)
        for client in data['clients']:
            formatted_clients[client['name']] = [client['cid'], "", "" , 0, 1, 100] #formatting the client list
    
    return formatted_clients  # returning the client list



clients = format_clients("clients.json")
print(clients)


try:
    server = MQTTS_SERVER("server","192.168.1.4",1883,clients)
    sleep(2)
    server.loop() # looping the server script

except:
    print("Server init faild!")




#clientdataFrame(clientID, pubKey, pvtKey, rollStart, rollStep, rollEnd)

#clist = {"client1":["001","","",0,1,100], "192.168.1.6":["002","","",0,1,100]}
