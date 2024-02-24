import numpy as np
import sys #basic library to interact with the Python interpreter.
#------------------------------------------------------------------------------------------------#


# Σταθερές

NUM_POSSIBLE_BYTE_VALUES = 256
BYTE_SIZE = 8

#------------------------------------------------------------------------------------------------#

# Αυτή η συνάρτηση επιχειρεί να ανακτήσει το κλειδί κρυπτογράφησης δεδομένων δύο 
# κρυπτογραφημένων κειμένων και των αντίστοιχων συνόλων χαρακτήρων τους. 
# Επιστρέφει μια λίστα με πιθανές τιμές για κάθε byte του κλειδιού.


def recover_cipher(cipher1, cipher2, charset1, charset2):
    """
    Function to recover the cipher using two ciphertexts and two character sets.
    """
    cipher1 = binary_to_np_array(cipher1)
    cipher2 = binary_to_np_array(cipher2)
    charset1 = np.frombuffer(charset1.encode(), dtype=np.uint8)
    charset2 = np.frombuffer(charset2.encode(), dtype=np.uint8)
    max_length = max(len(cipher1), len(cipher2))
    len_cipher1 = len(cipher1)
    len_cipher2 = len(cipher2)
    solutions = []
    for i in range(max_length):
        possible_values = [b for b in range(NUM_POSSIBLE_BYTE_VALUES) if (i >= len_cipher1 or np.isin(cipher1[i] ^ b, charset1)) and (i >= len_cipher2 or np.isin(cipher2[i] ^ b, charset2))]
        if not possible_values:
            return None
        solutions.append(np.array(possible_values))
    return solutions

#------------------------------------------------------------------------------------------------#

# Αυτή η συνάρτηση μετατρέπει μια δυαδική συμβολοσειρά σε έναν numpy πίνακα.


def binary_to_np_array(binary_str):
    """
    Function to convert a binary string to a numpy array.
    """
    return np.frombuffer(bytes(int(binary_str, 2)), dtype=np.uint8)


#------------------------------------------------------------------------------------------------#

# Αυτή η συνάρτηση μετατρέπει μια συμβολοσειρά απλού κειμένου στη δυαδική αναπαράστασή της.


def binary_representation(plaintext):
    """
    Function to get the binary representation of a plaintext.
    """
    binary_code = bin(int.from_bytes(plaintext, "big"))[2:]
    return binary_code.zfill((len(binary_code) + BYTE_SIZE - 1) // BYTE_SIZE * BYTE_SIZE)

#------------------------------------------------------------------------------------------------#

# Αυτή η συνάρτηση δημιουργεί δύο κρυπτογραφημένα κείμενα από δύο απλά κείμενα 
# χρησιμοποιώντας ένα κλειδί που δημιουργείται τυχαία.


def create_ciphertext(plaintext1, plaintext2):
    """
    Function to create a ciphertext from two plaintexts.
    """
    max_length = max(len(plaintext1), len(plaintext2))
    key = np.random.randint(NUM_POSSIBLE_BYTE_VALUES, size=max_length, dtype=np.uint8)
    cipher1 = np.bitwise_xor(key[:len(plaintext1)], np.frombuffer(plaintext1.encode(), dtype=np.uint8))
    cipher2 = np.bitwise_xor(key[:len(plaintext2)], np.frombuffer(plaintext2.encode(), dtype=np.uint8))
    print(f'Ciphertexts are:\n{binary_representation(cipher1)} {binary_representation(cipher2)}')

#------------------------------------------------------------------------------------------------#

# Αυτή η συνάρτηση επιστρέφει το σύνολο χαρακτήρων που αντιστοιχεί στο συγκεκριμένο όνομα.

def character_set(name):
    """
    Function to get the character set based on the name.
    """
    if name.lower() == 'num':
        return '0123456789'
    else:
        raise ValueError("Invalid character set name. Only 'num' is supported.")

#------------------------------------------------------------------------------------------------#

# Αυτή είναι η κύρια λειτουργία που εκτελεί το πρόγραμμα. 
# Αναλύει ορίσματα γραμμής εντολών και καλεί τις κατάλληλες συναρτήσεις με βάση τα ορίσματα.

def main():
    """
    Main function to run the program.
    """
    if len(sys.argv) < 5 and len(sys.argv) != 3:
        print(f'Usage is {sys.argv[0]} <PLAINTEXT1> <PLAINTEXT2> to display ciphertext as binary sequence')
        print(f'     and {sys.argv[0]} <CIPHERTEXT1> <CIPHERTEXT2> <CHARSET1> <CHARSET2> to decode ciphertext')
        print('CHARSET can be:')
        print('  num, for numerical plaintext 0-9')
        exit(1)
    if len(sys.argv) == 3:
        create_ciphertext(sys.argv[1], sys.argv[2])
        return
    if any(cset.lower() not in ['num'] for cset in sys.argv[3:4]):
        print('Valid character sets is only "num"')
        exit(4)
    solutions = recover_cipher(sys.argv[1], sys.argv[2], character_set(sys.argv[3]), character_set(sys.argv[4]))
    if solutions is None:
        print('No solution found, did you define character sets correctly?')
    else:
        total_solutions = 1
        for i, solution in enumerate(solutions, start=1):
            print(f'For the {i} key byte (bits {i*8} to {i*8+7}) the possible values values are:{solution}')
            total_solutions *= len(solution)
        print(f'\nTotal {total_solutions} solutions')


#------------------------------------------------------------------------------------------------#

# Αυτή η γραμμή ελέγχει εάν το σενάριο εκτελείται απευθείας (δεν εισάγεται) και αν ναι, 
# καλεί την κύρια συνάρτηση.

if __name__ == "__main__":
    main()