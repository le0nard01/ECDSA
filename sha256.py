from math import ceil,modf


initial_hash_values = [hex(int(modf(i**(1/2))[0] * (1 << 32))) 
                        for i in [2,3,5,7,11,13,17,19]]

initial_round_constants = [hex(int(modf(i**(1/3))[0] * (1 << 32))) 
                        for i in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311]]

def encode(string,tipo='str'): 
    def tobin(num): # transformar int em binario e preencher por 8, ou seja, tobin(10), 10 em binario é 1010, ele retornará 00001010.
        return ('00000000'[len(bin(num)[2:]):] 
                + bin(num)[2:])

    def rotate(data,tam): 
        if type(data) == int:
            data = bin(data)[2:]
        return data[len(data)-tam:]+data[0:len(data)-tam] # função de rightrotate-bitwise, mover X digitos da direita para esquerda.

    def shift(data,tam): return ('0'*(tam+1))+bin(int(data,2)>>tam)[2:] # função rightshift-bitwise, igual >>, só que faz a conversão para int antes.

    def s32(b): return (('0'*32)[:32-len(b)]+b) # preencher por 32, ou seja, s32, 10 em binario é 1010, ele retornará 00000000000000000000000000001010. 

    def formathash(h): # formatar os hex, para todos hex ter 8 digitos incrementando 0's. E depois junta-los
        final = ''
        for i in h:
            i=i[2:]
            final += i if len(i) == 8 else ('0'*8)[:8-len(i)]+i
        return final

    def message_Schedule(data):
        if len(data) % 512 != 0:
            print(f"Data não é particionada em 512. Tamanho: {len(data)}")
            return 0

        chunks = [ data[i:i+512] for i in range(0, len(data), 512) ] # Divide os chunks de 512
        
        (h0,h1,h2,h3,h4,h5,h6,h7) = [int(i[2:],16) for i in initial_hash_values] # cada letra é igual ao initial hash value

        for single_chunk in chunks:
            (a,b,c,d,e,f,g,h) = [bin(i)[2:] for i in (h0,h1,h2,h3,h4,h5,h6,h7)]
            (a,b,c,d,e,f,g,h) = [('0'*32)[0:(32-len(i))]+i for i in (a,b,c,d,e,f,g,h)] # acrescentar 0 para o total de len() = 32
    	
            chunk32 = [ single_chunk[i:i+32] for i in range(0, len(single_chunk), 32) ] #Dividir em chunks de 32

            for i in range(0,64-len(chunk32)): chunk32.append('0'*32) # acrescentar 0 para o total de len() = 32

            for i in range(16,64):  #parte 1 calculo sha256
                s0 = int(rotate(chunk32[i-15],7),2) ^ int(rotate(chunk32[i-15],18),2) ^ int(shift(chunk32[i-15],3),2)
                s1 = int(rotate(chunk32[i-2],17),2) ^ int(rotate(chunk32[i-2],19),2) ^ int(shift(chunk32[i-2],10),2)
                
                chunk32[i] = bin((int(chunk32[i-16],2) + s0 + int(chunk32[i-7],2) + s1) % (2**32))[2:]
                chunk32[i] = ('0'*(32-len(chunk32[i])))+chunk32[i]

            for i in range(0,64):   #parte 2 calculo sha256
                s1 = int(rotate(e,6),2) ^ int(rotate(e,11),2) ^ int(rotate(e,25),2)
                ch = (int(e,2) & int(f,2)) ^ ((~int(e,2)) & int(g,2))
                temp1 = int(h,2) + s1 + ch + int(initial_round_constants[i],16) + int(chunk32[i],2)
                temp1 = temp1 % (2**32)
                s0 = int(rotate(a,2),2) ^ int(rotate(a,13),2) ^ int(rotate(a,22),2)
                maj = (int(a,2) & int(b,2)) ^(int(a,2) & int(c,2)) ^ (int(b,2) & int(c,2))
                temp2 = (s0 + maj) % (2**32)
                
                h = s32(bin(int(g,2))[2:])
                g = s32(bin(int(f,2))[2:])
                f = s32(bin(int(e,2))[2:])
                e = s32(bin((int(d,2) + temp1) % (2**32))[2:])
                d = s32(bin(int(c,2))[2:])
                c = s32(bin(int(b,2))[2:])
                b = s32(bin(int(a,2))[2:])
                a = s32(bin((temp1+temp2) % (2**32))[2:])

            h0 = (h0 + int(a,2)) % (2**32)
            h1 = (h1 + int(b,2)) % (2**32)
            h2 = (h2 + int(c,2)) % (2**32)
            h3 = (h3 + int(d,2)) % (2**32)
            h4 = (h4 + int(e,2)) % (2**32)
            h5 = (h5 + int(f,2)) % (2**32)
            h6 = (h6 + int(g,2)) % (2**32)
            h7 = (h7 + int(h,2)) % (2**32)
            
        hashfinal = hex(h0),hex(h1),hex(h2),hex(h3),hex(h4),hex(h5),hex(h6),hex(h7)
        hashfinal = formathash(hashfinal)
        return hashfinal

    if tipo=='str':
        bits = [ tobin(ord(x)) for x in string ] # iterar a string passada e encaminhar pra funcao tobin
    elif tipo == 'hex':
        string = string if string[0:2] != '0x' else string[2:]
        bits = [ tobin(int(string[x-2:x],16)) for x in range(2,len(string)+1,2)]

    start_bits_len = len(''.join(bits)) #tamanho da string em bit
    
    bits.append('1') # adiciona 1 no final
    bits = ''.join(bits)

    zeros_512 = ceil((len(bits)+64)/512)*512 - len(bits) - 64 # completa com '0', por multiplos de 512 em relacao ao que couber do tamanho da string, - 64.
    
    bits += zeros_512*'0' 

    bits += '0'*(64-len(tobin(start_bits_len))) + tobin(start_bits_len) #adiciona o tamanho total no final dos bits e preenche.

    return message_Schedule(bits)
