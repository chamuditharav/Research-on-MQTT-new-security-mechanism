import paho.mqtt.client as mqtt
from threading import Thread
from time import sleep
import rsa


def generateKeys():
    (publicKey, privateKey) = rsa.newkeys(1024)
    return publicKey, privateKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        print("Decryption Error")


class MQTTS_CLIENT(Thread):
    client_id = ""
    client = None
    broker_ip = ""
    broker_port = 0
    client_nick = ""
    broker_tx = ""
    broker_rx = ""
    key_ex_status = False
    private_key = ""
    public_key = ""
    init_key_count = 0
    key_count = 0
    key_count_step = 1
    key_count_end = 100
    temp_roll_data = []


    def init_rolling_code_thread(self,start,step,end):
      if(self.key_ex_status == False):
        print("[!] Waiting for key exchange to proceed to rolling code initiation")
        sleep(2)
        self.init_rolling_code(start,step,end)
      else:
        try:
            self.init_key_count = start
            self.temp_roll_data = [start,step,end]
            dataFrame = f"{start}:{step}:{end}"
            dataFrame = encrypt(dataFrame, self.public_key)
            self.client.publish(self.broker_tx,f"INIT-ROLL:{self.client_nick}:{dataFrame.hex()}")
            #print(f"INIT-ROLL:{dataFrame}")
            #print(dataFrame)
        except:
          print("[-] Roling key set faild")

    def init_rolling_code(self,start,step,end):
      rolling_code_init_thread = Thread(target=self.init_rolling_code_thread, args=(start,step,end,))
      rolling_code_init_thread.start()

    def key_ex_init(self,public_key,private_key):
      try:
        self.private_key = private_key
        #print("thread...")
        pubK = str(public_key._save_pkcs1_pem().decode())
        pubKhex = public_key._save_pkcs1_pem().hex()
        self.client.publish(self.broker_tx,f"KEY_EXCHANGE_REQUEST:{self.client_nick}:{pubKhex}")
      except:
        print("[-] Ran into an error when exchanging keys")
        self.key_ex()

    def key_ex(self):
      try:
        publickey, privatekey = generateKeys()
        sleep(1)
        ket = Thread(target=self.key_ex_init, args=(publickey,privatekey))
        ket.start()
      except:
        print("[-] Key generation faild")
        self.key_ex()


    def on_message(self,client, userdata, msg):
      try:
        dataRec = str(msg.payload.decode())
        #print(dataRec)
        if(dataRec.split(":")[0] == "SVR-KEY_EXCHANGE_REPLY"):
          try:
            #print(dataRec[19:])
            pre_key = dataRec.split(":")[1]
            #print(bytes.fromhex(pre_key))
            key = rsa.PublicKey.load_pkcs1(bytes.fromhex(pre_key))
            self.public_key = key
            print("[+] Key exhanged !")
            self.key_count = 0
            self.key_ex_status = True
          except:
            print("[-] Faild to save public key")
            self.public_key = ""
            self.private_key = ""
            self.key_ex_status = False
            #self.key_ex()
        
        elif(dataRec == "SVR-ROLL-SUCC"):
          print("[+] Rolling Key set successfull")
          self.key_count = self.temp_roll_data[0]
          self.key_count_step = self.temp_roll_data[1]
          self.key_count_end = self.temp_roll_data[2]
          #print(self.key_count, self.key_count_step, self.key_count_end)
        
        elif(dataRec == "SVR-ROLL-FAIL"):
          print("[-] Rolling Key set faild")
        
        elif(dataRec == "SVR-ROLL-RST"):
          print("[!] Initiating Rolling Key Exchange")
          self.init_rolling_code(self.init_key_count, self.key_count_step, self.key_count_end)

        elif(dataRec == "SVR-INIT"):
          print("[+] Initiating Key Exchange")
          self.key_ex()
        
        elif(dataRec.split(":")[0] == "UNENC-SVR-MSG-HAND"):
          print(f'UNENC >> {dataRec.split(":")[1]} -- {dataRec.split(":")[2]}')

        elif(dataRec.split(":")[0] == "ENC-SVR-MSG-HAND"):
          try:
            unenc_data = decrypt(bytes.fromhex(dataRec.split(":")[1]), self.private_key)
            print(f'ENC >> {unenc_data.split(":")[0]} -- {unenc_data.split(":")[1]}')
          except:
            print("[!] Courroupted data")
      
      except:
        print("[!] Unexpected data recieved")


    def sendUnencMSG(self, msg, dest):
      try:
        dataFrame = f"{self.client_id}:{self.client_nick}:{dest}:{msg}"
        #print(dataFrame)
        self.client.publish(self.broker_tx,f"UNENC:{dataFrame}")
        print("[+] Msg sent!")
      except:
        print("[-] Couldn't send unencrypted msg")

    def sendEncMSG(self,msg,dest):
      if(self.public_key == ""):
        print("[-] Cannot send encrypted msg without a proper key exchange")
      else:
        dataFrame = f"{self.client_id}:{self.client_nick}:{dest}:{msg}"
        cipher_msg = encrypt(dataFrame,self.public_key)
        cipher_count = encrypt(str(self.key_count), self.public_key)
        
        #print(f"ENC:{dataFrame}:{cipher_msg.hex()}:{cipher_count.hex()}")
        self.client.publish(self.broker_tx,f"ENC:{self.client_nick}:{cipher_msg.hex()}:{cipher_count.hex()}")

        if(self.key_count >= self.key_count_end):self.key_count = 0
        else: self.key_count += self.key_count_step

        print("[+] Msg sent!")



    def loop(self):
      self.client.loop_start()

    def __init__(self, clientID, client_nick, broker_ip, broker_port, stream="mqqts"):
      self.client_id = clientID
      self.broker_ip = broker_ip
      self.broker_port = broker_port
      self.client_nick = client_nick
      self.broker_tx = f"{broker_ip}/tx"
      #self.broker_rx = f"{client_nick}/{stream}/rx"
      self.broker_rx = f"{client_nick}/rx"
      
      try:
        sleep(2)
        self.client = mqtt.Client()
        self.client.connect(self.broker_ip,self.broker_port)
        self.client.on_connect = print("[+] Connected to the Server")
        self.client.on_message = self.on_message
        self.client.subscribe(self.broker_rx)
      except:
        print("[-] Connection faild!")

    def showConfig(self):
      print(f"Client ID : {self.client_id}")
      print(f"Broker    : {self.broker_ip}:{self.broker_port}")
      print(f"MSG TX    : {self.broker_tx}")
      print(f"MSG RX    : {self.broker_rx}")



client = MQTTS_CLIENT("002","client2", "192.168.1.4", 1883, "mqtt")
client.sendUnencMSG("Hello from client 2","client1")
client.loop()
#client.showConfig()
client.key_ex()
sleep(1)
client.init_rolling_code(100,1,150)
sleep(10)
client.sendEncMSG("Cipher test msg!","client1")

while(True):
  #client.init_rolling_code(100,10,1000)

  client.sendEncMSG("Encrypted Hello from Client 2","client1")
  sleep(10)
  client.sendUnencMSG("Unencrypted Hello from client 2","client1")
  
  sleep(5)
