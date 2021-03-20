import secrets
#from hashlib import sha256
from sha256 import encode as sha256encode

# resolver bug base58decode.

class ChavePrivada():
    def __init__(self) -> None:
        self.ChaveHex = ''
        self.CheckSum = ''
        self.ChaveWIF = ''

    def random256(self): #random metodo com lib secrets.
        r = hex(secrets.randbits(8*32))[2:] # 32 bytes | 256 bits
        try: return r if (len(bytes.fromhex(r)) == 32) else self.random256() #checagem do tamanho do r
        except: return self.random256()
 
    def Gerar(self,randomnum=None):

        if randomnum==None:
            randomnum = self.random256() #checagem se foi pré-inserido a chave aleatoria

        else: #interpretação do parametropassado
            if type(randomnum) == int and len(bytes.fromhex(hex(randomnum))) == 256: #como int
                randomnum = hex(randomnum)[2:]
            elif type(randomnum) == str and randomnum[0:2] == '0x' and len(bytes.fromhex(randomnum[2:])) == 256: #como hex com '0x'
                randomnum = randomnum[2:]
            else:
                try:
                    len(bytes.fromhex(randomnum)) == 256 #como hex sem '0x'
                except:
                    raise ValueError('Chave-privada invalida.')

        self.ChaveHex = randomnum
        self.WIF(randomnum)

    def WIF(self, chavehex):    # https://en.bitcoin.it/wiki/Wallet_import_format
        #Conceito:
        # ('0x80' + CHAVE_PRIVADA) -> SHA256 -> SHA256 -> resultado (PEGAR OS 4 PRIMEIROS BYTES) que virará o checksum
        # ChaveWIF = BASE58(CHAVEPRIVADA + CHESUM)

        if chavehex[:2] == '0x': chavehex[2:]
        chavehex = '80'+chavehex
        try:
            #shahash  = sha256(bytes.fromhex(chavehex)).hexdigest()
            #shahash2 = sha256(bytes.fromhex(shahash)).hexdigest()
            shahash = sha256encode(chavehex,'hex')
            shahash2 = sha256encode(shahash,'hex')
            checksum = bytes.fromhex(shahash2)[0:4].hex()
            self.ChaveWIF = self.base58encode('0x'+ chavehex.lower() + checksum.lower())
            self.CheckSum = checksum
        except TypeError as t: print(t)

    def base58encode(self,num):   # https://learnmeabitcoin.com/technical/base58
        StringBase = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        TamBase = len(StringBase)

        if TamBase != 58:
            print(f"Erro inexperado, verificar StringBase | len(StringBase): {len(StringBase)}")
            
        if type(num) != int: 
            try:
                if type(num) == str and num[:2]!='0x': # str para int
                    num = int(num.encode().hex(),16)
                if type(num) == str and num[:2]=='0x': # hex para int
                    num = int(num, 16)
            except:
                raise ValueError(f'O tipo {type(num)} é invalido')

        num_comeco = num
        string = ''

        while num>=1:
            sobra = (num % TamBase) #MODULO int(chaveprivada) % 58
            num = (num // TamBase) # Divisão int
            string = string + StringBase[sobra]

        if self.base58decode(string[::-1]) != num_comeco:
            print(f'Problema inesperado com checkagem de Base58! diferença: {self.base58decode(string[::-1])-num_comeco}')
        
        return string[::-1] # inverter
        

    def base58decode(self,encoded):   # https://learnmeabitcoin.com/technical/base58
        encoded = (encoded[::-1]) # inverter parametro base58. Já que a string é passada [::-1] invertida.

        StringBase = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        TamBase = len(StringBase)
        
        if TamBase != 58:
            print(f"Erro inexperado, verificar StringBase | len(StringBase): {len(StringBase)}")
            
        if type(encoded) != str: 
            raise ValueError(f'O tipo {type(encoded)} é invalido')

        num = 0

        for e,i in list(enumerate(encoded)): #Enumerate + Base58encodada invertido. 
            letra_value = StringBase.find(i) 
            num += letra_value*(TamBase**e) #numero = numero + index da letra * 58 ** enumerate
        return num
        

#Checagem de funcionamento
_checagem = ChavePrivada()
_checagem.Gerar('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D') #Essa é uma chave privada para teste. Não importe essa chave!
if _checagem.ChaveWIF != '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ':
    print("Programa quebrado por algum erro inesperado, funcionamento invalido. Não use!")
