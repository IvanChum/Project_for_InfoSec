import pickle
import binascii
from os.path import dirname


class Kuznyechik:
    """
    Implementation of a block cipher Kuznyechik GOST R 34.12-2015
    """

    def __init__(self, key):
        """
        :param key: 256 bit key, string format
        """
        key = list(binascii.unhexlify(key))  # convert string to list of hex
        # substitution value
        self.PI = (252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
                   153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
                   139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44,
                   81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191,
                   114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
                   178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
                   62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220,
                   232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
                   173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
                   29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
                   202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
                   116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182)

        # reverse substitution value
        self.PI_INV = list(self.PI)
        for i in range(256):
            self.PI_INV[self.PI[i]] = i

        # precomputed table with multiplication results in field x^8 + x^7 + x^6 + x + 1
        f = open(dirname(__file__) + '/multiplication_tables', 'rb')
        self.multtable = pickle.load(f)
        f.close()

        # Constants for reamer key
        self.C = [self.l_transform([0] * 15 + [i]) for i in range(1, 33)]

        #  generation of reamer key
        self.roundkey = [key[:16], key[16:]]
        self.roundkey = self.roundkey + self.keyschedule(self.roundkey)

    @staticmethod
    def add_x_to_y_field(x, y):
        """
        Sum x to y in field x^8 + x^7 + x^6 + x + 1.
        :param x: fist addend
        :param y: second addend
        :return: result of summation
        """
        return x ^ y

    @staticmethod
    def sum_elements_from_list_field(x):
        """
        Sum of all elements of x in field x^8 + x^7 + x^6 + x + 1.
        :param x: list of elements.
        :return: result of summation
        """
        s = 0
        for a in x:
            s ^= a
        return s

    @staticmethod
    def mult_x_by_y_field(x, y):
        """
        Multiplication of x by y in field x^8 + x^7 + x^6 + x + 1.
        :param x: first multiplier
        :param y: second multiplier
        :return: result of multiplication
        """
        p = 0
        while x:
            if x & 1:
                p ^= y
            if y & 0x80:
                y = (y << 1) ^ 0x1C3
            else:
                y <<= 1
            x >>= 1
        return p

    @staticmethod
    def x_transform(x, k):
        """XOR of binary strings x and k"""
        return [x[i] ^ k[i] for i in range(len(k))]

    def s_transform(self, x):
        """Replace each byte x in accordance with table PI"""
        return [self.PI[x[i]] for i in range(len(x))]

    def s_inv_transform(self, x):
        """Replace each byte x in accordance with table PI_INV"""
        return [self.PI_INV[i] for i in x]

    def linear_transform(self, x):
        """Makes a byte array of one byte using pre-calculated table"""
        consts = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
        multiplication = [self.multtable[x[i]][consts[i]] for i in range(len(x))]
        return self.sum_elements_from_list_field(multiplication)

    def r_transform(self, x):
        """R transform"""
        return [self.linear_transform(x), ] + x[:-1]

    def r_inv_transform(self, x):
        """Inverse R transformation"""
        return x[1:] + [self.linear_transform(x[1:] + [x[0], ]), ]

    def l_transform(self, x):
        """Consistent implementation of the R transform 16 times"""
        for i in range(len(x)):
            x = self.r_transform(x)
        return x

    def l_inv_transform(self, x):
        """Inverse L transformation"""
        for i in range(len(x)):
            x = self.r_inv_transform(x)
        return x

    def f_transform(self, k, a):
        """F transform для развертки ключа"""
        tmp = self.x_transform(k, a[0])
        tmp = self.s_transform(tmp)
        tmp = self.l_transform(tmp)
        tmp = self.x_transform(tmp, a[1])
        return [tmp, a[0]]

    def keyschedule(self, roundkey):
        """Generates a reamer of the key rounds"""
        roundkeys = []
        for i in range(4):
            for k in range(8):
                roundkey = self.f_transform(self.C[8 * i + k], roundkey)
            roundkeys.append(roundkey[0])
            roundkeys.append(roundkey[1])
        return roundkeys

    def encrypt(self, m):
        """
        Encrypts message.
        :param m: string in hex format
        :return: encrypted message.
        """
        m = list(binascii.unhexlify(m))
        for i in range(9):
            m = self.x_transform(m, self.roundkey[i])
            m = self.s_transform(m)
            m = self.l_transform(m)
        m = self.x_transform(m, self.roundkey[9])
        return binascii.hexlify(bytearray(m))

    def decrypt(self, c):
        """
        Decrypts message.
        :param c: string in hex format.
        :return: decrypted message.
        """
        c = list(binascii.unhexlify(c))
        for i in range(9, 0, -1):
            c = self.x_transform(c, self.roundkey[i])
            c = self.l_inv_transform(c)
            c = self.s_inv_transform(c)
        c = self.x_transform(c, self.roundkey[0])
        return binascii.hexlify(bytearray(c))
