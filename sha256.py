from math import ceil,modf

initial_hash_values = [hex(int(modf(i**(1/2))[0] * (1 << 32))) 
                        for i in [2,3,5,7,11,13,17,19]]

initial_round_constants = [hex(int(modf(i**(1/3))[0] * (1 << 32))) 
                        for i in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311]]

def sha256(string): # https://qvault.io/2020/07/08/how-sha-2-works-step-by-step-sha-256/
    def tobin(num): # transformar int em binario e preencher por 8, ou seja, tobin(10), 10 em binario é 1010, ele retornará 00001010.
        return ('00000000'[len(bin(num)[2:]):] 
                + bin(num)[2:])

    def rotate(data,tam): return data[len(data)-tam:]+data[0:len(data)-tam]

    def shift(data,tam): return ('0'*(tam+1))+bin(int(data,2)>>tam)[2:]

    def s32(b):
        return (('0'*32)[:32-len(b)]+b)

    def message_Schedule(data):
        if len(data) % 512 != 0:
            print(f"Data não é particionada em 512. Tamanho: {len(data)}")
            return 0

        chunks = [ data[i:i+512] for i in range(0, len(data), 512) ] # Divide os chunks de 512
        (h0,h1,h2,h3,h4,h5,h6,h7) = [bin(int(i[2:],16))[2:] for i in initial_hash_values] # cada letra é igual ao initial hash value
        (h0,h1,h2,h3,h4,h5,h6,h7) = [('0'*32)[0:(32-len(i))]+i for i in (h0,h1,h2,h3,h4,h5,h6,h7)] # acrescentar 0 para o total de len() = 32

        for single_chunk in chunks:
            #x = """01101000011001010110110001101100 01101111001000000111011101101111 01110010011011000110010010000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000001011000 00110111010001110000001000110111 10000110110100001100000000110001 11010011101111010001000100001011 01111000001111110100011110000010 00101010100100000111110011101101 01001011001011110111110011001001 00110001111000011001010001011101 10001001001101100100100101100100 01111111011110100000011011011010 11000001011110011010100100111010 10111011111010001111011001010101 00001100000110101110001111100110 10110000111111100000110101111101 01011111011011100101010110010011 00000000100010011001101101010010 00000111111100011100101010010100 00111011010111111110010111010110 01101000011001010110001011100110 11001000010011100000101010011110 00000110101011111001101100100101 10010010111011110110010011010111 01100011111110010101111001011010 11100011000101100110011111010111 10000100001110111101111000010110 11101110111011001010100001011011 10100000010011111111001000100001 11111001000110001010110110111000 00010100101010001001001000011001 00010000100001000101001100011101 01100000100100111110000011001101 10000011000000110101111111101001 11010101101011100111100100111000 00111001001111110000010110101101 11111011010010110001101111101111 11101011011101011111111100101001 01101010001101101001010100110100 00100010111111001001110011011000 10101001011101000000110100101011 01100000110011110011100010000101 11000100101011001001100000111010 00010001010000101111110110101101 10110000101100000001110111011001 10011000111100001100001101101111 01110010000101111011100000011110 10100010110101000110011110011010 00000001000011111001100101111011 11111100000101110100111100001010 11000010110000101110101100010110"""
            #x = x.split(' ')
            
            chunk32 = [ single_chunk[i:i+32] for i in range(0, len(single_chunk), 32) ] #Dividir em chunks de 32

            for i in range(0,64-len(chunk32)): chunk32.append('0'*32) # acrescentar 0 para o total de len() = 32
            for i in range(16,64):  #parte 1 calculo sha256
                s0 = int(rotate(chunk32[i-15],7),2) ^ int(rotate(chunk32[i-15],18),2) ^ int(shift(chunk32[i-15],3),2)
                s1 = int(rotate(chunk32[i-2],17),2) ^ int(rotate(chunk32[i-2],19),2) ^ int(shift(chunk32[i-2],10),2)
                
                chunk32[i] = bin((int(chunk32[i-16],2) + s0 + int(chunk32[i-7],2) + s1) % (2**32))[2:]
                chunk32[i] = ('0'*(32-len(chunk32[i])))+chunk32[i]

            (a,b,c,d,e,f,g,h) = (h0,h1,h2,h3,h4,h5,h6,h7)

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

                #h1 = '00011111100000111101100110101011'
                #g1 = '10011011000001010110100010001100'
                #f1 = '01010001000011100101001001111111'
                #e1 = '00000001001011010100111100001110'
                #d1 = '00111100011011101111001101110010'
                #c1 = '10111011011001111010111010000101'
                #b1 = '01101010000010011110011001100111'
                #a1 = '01100100011011011111010010111001'
                #print(a == a1)
                #print(b == b1)
                #print(c == c1)
                #print(d == d1)
                #print(e == e1)
                #print(f == f1)
                #print(g == g1)
                #print(h == h1)

            print(hex(int(a,2)),hex(int(b,2)),hex(int(c,2)),hex(int(d,2)),hex(int(e,2)),hex(int(f,2)),hex(int(g,2)),hex(int(h,2)))
            #initial_hash_values

    bits = [ tobin(ord(x)) for x in string ] # iterar a string passada e encaminhar pra funcao tobin

    start_bits_len = len(''.join(bits)) #tamanho da string em bit
    
    bits.append('1') # adiciona 1 no final
    bits = ''.join(bits)

    zeros_512 = ceil((len(bits)+64)/512)*512 - len(bits) - 64 # completa com '0', por multiplos de 512 em relacao ao que couber do tamanho da string, - 64.
    
    bits += zeros_512*'0' 

    bits += '0'*(64-len(tobin(start_bits_len))) + tobin(start_bits_len) #adiciona o tamanho total no final dos bits e preenche.

    message_Schedule(bits)

sha256('hello world')