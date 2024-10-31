import random
import hashlib
 
BASE58 = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'

def Candidate():
    srandom = random.SystemRandom()
    return('%s%s' % ('S', ''.join([BASE58[ srandom.randrange(0,len(BASE58)) ] for i in range(21)])))

def GenerateKeys(numKeys = 1):
    """
    Generate mini private keys and output the mini key as well as the full
    private key. numKeys is The number of keys to generate, and
    """
    keysGenerated = 0
    totalCandidates = 0
    while keysGenerated < numKeys:
        try:
            cand = Candidate()
            # Do typo check
            t = '%s?' % cand
            # Take one round of SHA256
            candHash = hashlib.sha256(t.encode('utf-8')).digest()
            # Check if the first eight bits of the hash are 0
            if candHash[0] == 0:
                privateKey = GetPrivateKey(cand)
                print(f'\n{cand}\nSHA256(): {privateKey}\nsha256(?): {candHash.hex()}')
                if CheckShortKey(cand):
                    print('Validated.')
                else:
                    print('Invalid!')
                keysGenerated += 1
            totalCandidates += 1
        except KeyboardInterrupt:
            break
    
    print(f'\nKeys Generated: {keysGenerated}\nTotal Candidates: {totalCandidates}\nReject Percentage: {100 * (1.0 - keysGenerated / float(totalCandidates)):.1f}')

 
def GetPrivateKey(shortKey):
    """
    Returns the hexadecimal representation of the private key corresponding
    to the given short key.
    """
    if CheckShortKey(shortKey):
        return hashlib.sha256(shortKey.encode('utf-8')).hexdigest()
    else:
        print('Typo detected in private key!')
        return None
 
def CheckShortKey(shortKey):
    """
    Checks for typos in the short key.
    """
    if len(shortKey) != 22:
        return False
    t = f'{shortKey}?'
    tHash = hashlib.sha256(t.encode('utf-8')).digest()
    # Check to see that first byte is \x00
    return tHash[0] == 0

GenerateKeys()