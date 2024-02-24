import numpy as np
import sys

NUM_POSSIBLE_BYTE_VALUES = 256
BYTE_SIZE = 8

# NUM_POSSIBLE_BYTE_VALUES: Έχει οριστεί σε 256 και αφορά τον αριθμό των πιθανών τιμών που μπορεί να έχει ένα byte.
# BYTE_SIZE: Ορίζει των αριθμό των bit (8) που αποτελείται το ένα byte. 


def recover_cipher(cipher1, cipher2, charset1, charset2):
    assert len(cipher1) % BYTE_SIZE == 0 and len(cipher2) % BYTE_SIZE == 0, "Ciphertext length should be multiple of BYTE_SIZE"
    assert all(c in '01' for c in cipher1 + cipher2), "Ciphertext should be binary coded"
    cipher1 = np.frombuffer(bytes(int(cipher1, 2)), dtype=np.uint8)
    cipher2 = np.frombuffer(bytes(int(cipher2, 2)), dtype=np.uint8)
    charset1 = np.frombuffer(charset1.encode(), dtype=np.uint8)
    charset2 = np.frombuffer(charset2.encode(), dtype=np.uint8)
    max_length = max(len(cipher1), len(cipher2))
    solutions = []
    for i in range(max_length):
        possible_values = [b for b in range(NUM_POSSIBLE_BYTE_VALUES) if (i >= len(cipher1) or (cipher1[i] ^ b) in charset1) and (i >= len(cipher2) or (cipher2[i] ^ b) in charset2)]
        if not possible_values:
            return None
        solutions.append(possible_values)
    return solutions


# Η συνάρτηση recover_cipher(cipher1, cipher2, charset1, charset2) , 
# προσπαθεί να ανακτήσει το αρχικό κλειδί που χρησιμοποιείται για την 
# κρυπτογράφηση συγκρίνοντας δύο κρυπτογραφημένα κείμενα και τα αντίστοιχα 
# σύνολα χαρακτήρων τους. Επιστρέφει μια λίστα με πιθανές τιμές byte για κάθε byte στο κλειδί.


def binary_representation(plaintext):
    binary_code = bin(int.from_bytes(plaintext, "big"))[2:]
    return f"{binary_code:0>{len(binary_code) + BYTE_SIZE - 1 // BYTE_SIZE * BYTE_SIZE}}"

# Με τη binary_representation(plaintext) γίνεται μετατροπή μιας συμβολοσειράς απλού κειμένου σε δυαδική (binary) μορφή.


def create_ciphertext(plaintext1, plaintext2):
    max_length = max(len(plaintext1), len(plaintext2))
    key = np.random.randint(NUM_POSSIBLE_BYTE_VALUES, size=max_length, dtype=np.uint8)
    cipher1 = np.bitwise_xor(key[:len(plaintext1)], np.frombuffer(plaintext1.encode(), dtype=np.uint8))
    cipher2 = np.bitwise_xor(key[:len(plaintext2)], np.frombuffer(plaintext2.encode(), dtype=np.uint8))
    print(f'Ciphertexts are:\n{binary_representation(cipher1)} {binary_representation(cipher2)}')


# Ακολουθεί η create_ciphertext(plaintext1, plaintext2), 
# όπου δημιουργεί δύο κρυπτογραφημένα κείμενα από δύο plaintext, 
# χρησιμοποιώντας ένα κλειδί το οποίο δημιουργείται τυχαία και έπειτα γίνεται εξαγωγή αυτών σε δυαδική μορφή.

def character_set(name):
    if name.lower() == 'num':
        return '0123456789'

# Η character_set(name) ως συνάρτηση επιστρέφει μια σειρά χαρακτήρων 
# με βάση το παρεχόμενο όνομα. Υποστηρίζει μόνο το "num" (numpad), 
# το οποίο επιστρέφει μια σειρά ψηφίων από το 0 έως το 9.


def main():
    if len(sys.argv) < 5 and len(sys.argv) != 3:
        print(f'Usage is {sys.argv[0]} <PLAINTEXT1> <PLAINTEXT2> to display ciphertext as binary sequence')
        print(f'     and {sys.argv[0]} <CIPHERTEXT1> <CIPHERTEXT2> <CHARSET1> <CHARSET2> to decode ciphertext')
        print('CHARSET can be:')
        print('  num, for numerical plaintext 0-9')
        exit(1)
    if len(sys.argv) == 3:
        create_ciphertext(sys.argv[1], sys.argv[2])
        return
    if len(sys.argv[1]) % BYTE_SIZE != 0 or len(sys.argv[2]) % BYTE_SIZE != 0:
        print('Ciphertexts must have multiple of BYTE_SIZE bits')
        exit(2)
    if not all(c in '01' for c in sys.argv[1] + sys.argv[2]):
        print('Ciphertexts must be binary coded')
        exit(3)
    if any(cset.lower() not in ['num'] for cset in sys.argv[3:4]):
        print('Valid character sets is only "num"')
        exit(4)
    solutions = recover_cipher(sys.argv[1], sys.argv[2], character_set(sys.argv[3]), character_set(sys.argv[4]))
    if solutions is None:
        print('No solution found, did you define character sets correctly?')
    else:
        total_solutions = 1
        for i in range(len(solutions)):
            print(f'For the {i+1} key byte (bits {i*BYTE_SIZE} to {i*BYTE_SIZE+BYTE_SIZE-1}) the possible values values are:{solutions[i]}')
            total_solutions *= len(solutions[i])
        print(f'\nTotal {total_solutions} solutions')

# H συνάρτηση main() ελέγχει για το αν θα εκτελεστεί κρυπτογράφηση ή αποκρυπτογράφηση. 
# Στη διαδικασία της κρυπτογράφησης, παίρνει ως όρισμα δύο απλά κείμενα ως είσοδο και εκτυπώνει 
# τα αντίστοιχα κρυπτογραφημένα κείμενα ενώ στη διαδικασία της αποκρυπτογράφησης, παίρνει δύο κρυπτογραφημένα κείμενα και δύο σύνολα χαρακτήρων 
# ως είσοδο και προσπαθεί να ανακτήσει το αρχικό κλειδί. Οι δύο τρόποι κατά τους οποίους λειτουργεί το script και τους καλούμε από ένα command line (cmd), είναι:

# Για κρυπτογράφηση: 
# python exercise_2a.py <PLAINTEXT1> <PLAINTEXT2>
#-----------------------------------------------------------------------------------------------------------------#
# Για αποκρυπτογράφηση: 
# python exercise_2a.py <CIPHERTEXT1> <CIPHERTEXT2> <CHARSET1> <CHARSET2>


if __name__ == "__main__":
    main()
