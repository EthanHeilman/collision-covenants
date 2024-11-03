import hashlib, random, math, time
from Crypto.Hash import RIPEMD160
from hashlib import blake2b
from hashlib import blake2s


# Change this to adjust the hash size in bits
hashSizeBytes = 5 #48/8

def sha1(x):
    # We switched from sha1 and ripemd160 to blake2b, blake2s for speed. 
    # It should not impact the results because we are assume an ideal hash function anyways
    # return hashlib.sha1(x).digest()
    h = blake2b(digest_size=hashSizeBytes)
    h.update(x)
    return h.digest()

def ripemd160(x):
    # hash = RIPEMD160.new()
    # hash.update(x)
    # digest = hash.digest()
    # return digest
    h = blake2s(digest_size=hashSizeBytes)
    h.update(x)
    return h.digest()

def truncate(y, amount):
    return y[0:amount]

dInternalCount = 0
def dGen(w, t):
    global dInternalCount
    y = w
    for bit in t:
        dInternalCount += 1
        if bit == 0:
            y = truncate(sha1(y), hashSizeBytes)
        if bit == 1:
            y = truncate(ripemd160(y), hashSizeBytes)
    return y


# Switched from this to about 150% faster version below.
# def bytesToBitSeq(bytesVal):
#     bitSeq = [int(bit) for byte in bytesVal for bit in f'{byte:08b}'] # Suggested by chatGpt4o, had to tweak it. Better than the stackoverflow answer tho.
#     return bitSeq 

# Turns a byte array into a bit sequence, this version proposed by ChatGPT4o
def bytesToBitSeq(bytesVal):
    num_bits = len(bytesVal) * 8
    bits = [0] * num_bits  # Preallocate the list
    index = 0
    for byte in bytesVal:
        bits[index]     = (byte >> 7) & 1
        bits[index + 1] = (byte >> 6) & 1
        bits[index + 2] = (byte >> 5) & 1
        bits[index + 3] = (byte >> 4) & 1
        bits[index + 4] = (byte >> 3) & 1
        bits[index + 5] = (byte >> 2) & 1
        bits[index + 6] = (byte >> 1) & 1
        bits[index + 7] = byte & 1
        index += 8
    return bits

fCount = 0
def f(xBytes, c, wSize, tSize):
    global fCount
    fCount += 1
    x = bytesToBitSeq(xBytes)
    w = bytes(x[c: c+wSize])
    t = x[c+wSize+1: c+wSize+tSize+1]
    return dGen(w, t)

gCount = 0
def g(xBytes):
    global gCount
    gCount += 1
    return truncate(sha1(b"bitcoinTransactionTemplateO_o:"+xBytes), hashSizeBytes)

hCount = 0
def h(xBytes, c, wSize, tSize):
    global hCount
    hCount += 1
    x = bytesToBitSeq(xBytes)
    if isG(x, c):
        return g(xBytes)
    return f(xBytes, c, wSize, tSize)

def isG(x, c):
    for i in x[0:c]:
        if i != 0:
            return True
    return False

# Checks if rho is distinguished point
def isDP(rho, z):
    rhoBitSeq = bytesToBitSeq(rho)

    if rhoBitSeq[len(rhoBitSeq)-z:] == [0 for i in range(z)]:
        return True
    return False

def parallelRun(c, z, wSize, tSize, dpTable):
    rho = random.randbytes(hashSizeBytes)
    prevTable = {}
    start = rho

    while True:
        y = h(rho, c, wSize, tSize)
        prevTable[y] = rho
        if isDP(y, z):
            if y in dpTable:
                dpStart = dpTable[y]
                x2 = dpStart
                while (x2 != y):
                    y2 = h(x2, c, wSize, tSize)
                    if y2 in prevTable:
                        break
                    x2 = y2
                assert(y2 in prevTable)
                return x2, prevTable[y2]
            else:
                dpTable[y] = start
                rho = start
                prevTable = {}
        rho = y

def findCol(c, z, wSize, tSize):
    ffColCount = 0
    ggColCount = 0

    dpTable = {}
    # Run until we find a collision that lets us spend the covenant
    while True:
        # x1 and x2 are the inputs that result in a collision
        x1Bytes, x2Bytes = parallelRun(c, z, wSize, tSize, dpTable)
        if x1Bytes == x2Bytes:
            # The hash function sizes we are dealing with a small enough that sometimes we get a collision in the input rather than the output. If that happens, we just run it again.
            continue

        x1 = bytesToBitSeq(x1Bytes)
        x2 = bytesToBitSeq(x2Bytes)

        if isG(x1, c) and isG(x2, c):
            ggColCount += 1
            # print ("useless G G collision", bytes.hex(x1Bytes), bytes.hex(x2Bytes))
        elif not isG(x1, c) and not isG(x2, c):
            ffColCount += 1
            # print ("useless F F collision", bytes.hex(x1Bytes), bytes.hex(x2Bytes))
        else:
            print ("Useful F G collision", bytes.hex(x1Bytes), bytes.hex(x2Bytes))
            return x1Bytes, x2Bytes, len(dpTable), ffColCount, ggColCount


def approxLog2(n):
    # Useful to not have to check if a value is zero each time you use math.log2. Should be used with care.
    if n == 0: return 0
    return math.log2(n)


def test():
    # Some very simple unit tests for the functions
    w1 = bytes.fromhex('00aa11bb')
    t1 = [1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0]
    d1 = dGen(w1, t1)

    w2 = bytes.fromhex('00aa11bb')
    t2 = [0,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0]
    d2 = dGen(w2, t2)

    w3 = bytes.fromhex('ffffffff')
    t3 = [0,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0]
    d3 = dGen(w3, t3)

    assert(d1 != d2)
    assert(d2 != d3)

    res1 = bytesToBitSeq(bytes.fromhex('00'))
    res2 = bytesToBitSeq(bytes.fromhex('01'))
    res3 = bytesToBitSeq(bytes.fromhex('aa0f'))
    assert(res1 == [0, 0, 0, 0, 0, 0, 0, 0])
    assert(res2 == [0, 0, 0, 0, 0, 0, 0, 1])
    assert(res3 == [1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1])

    rho1 = f(bytes.fromhex('aaaaaaaaaaaaaaaaaa'), 1, 33, 40)
    assert(len(rho1) == hashSizeBytes)

    rho2 = f(bytes.fromhex('ffffffffffffffffff'), 1, 33, 40)
    assert(rho2 != rho1)

    rho3 = g(bytes.fromhex('aaaaaaaaaaaaaaaaaa'))
    assert(len(rho3) == hashSizeBytes)
    assert(rho3 != rho2)

    rho4 = g(bytes.fromhex('ffffffffffffffffff'))
    assert(rho4 != rho3)

    assert(h(bytes.fromhex('00ffffffffffffffff'), 1, 33, 40) == f(bytes.fromhex('00ffffffffffffffff'), 1, 33, 40))
    assert(h(bytes.fromhex('ffffffffffffffffff'), 1, 33, 40) == g(bytes.fromhex('ffffffffffffffffff')))

    c = 5 # f queries vs g queries
    z = 6
    wSize = 10
    tSize = 20

    start = int(time.time())
    x1, x2, pTableSize, ffColCount, ggColCount = findCol(c, z, wSize, tSize)
    assert(h(x1, c, wSize, tSize) == h(x2, c, wSize, tSize))
    assert(x1 != x2)
    stop = int(time.time())

    print(bytes.hex(x1), bytes.hex(x2), bytes.hex(h(x1, c, wSize, tSize)), bytes.hex(h(x2, c, wSize, tSize)))
    print(hashSizeBytes,  approxLog2(fCount), approxLog2(gCount), approxLog2(hCount), approxLog2(pTableSize), approxLog2(ffColCount), approxLog2(ggColCount), math.floor((stop-start)/60))


# Computes the expected cost for the following parameters.
def PredictedCostEq(c, z, wSize, tSize):
    n = hashSizeBytes*8

    # This is not a bug, log2Tsize is the log2 of the number of bits in t. We use this to bring the cost of the hash queries internal to dGen into the exponent
    log2Tsize = math.log2(tSize)
    qfLog2 = (n-c)/2
    qgLog2 = n - qfLog2

    workLog2 = math.log2(
        2**(qfLog2 + log2Tsize) 
        + 2**(n-qfLog2) 
        +2**(2*qfLog2+log2Tsize+z-wSize-tSize-1) 
        + 2**(2*(n-qfLog2)+z-n-1))

    return workLog2, qfLog2, qgLog2


def run(c, z, wSize, tSize):
    start = int(time.time())
    x1, x2, pTableSize, ffColCount, ggColCount = findCol(c, z, wSize, tSize)
    assert(h(x1, c, wSize, tSize) == h(x2, c, wSize, tSize))
    assert(x1 != x2)
    stop = int(time.time())

    hashQueries =  dInternalCount + hCount
    print(bytes.hex(x1), bytes.hex(x2), bytes.hex(h(x1, c, wSize, tSize)), bytes.hex(h(x2, c, wSize, tSize)))
    print(wSize, tSize, c, approxLog2(hashQueries), approxLog2(ffColCount), approxLog2(ggColCount), math.floor((stop-start)))

    return math.log2(hashQueries)

def graph():
    wSize = 10
    z=3

    numSamplesPerT = 20
    samples = []
    xSamples = []
    xEq = []
    yEq = []

    for witnessSize in range(20, round(hashSizeBytes*8)-1, 2):
        tSize = witnessSize - wSize
        # Choose c to ensure a balanced number of collisions between f and g
        c = round((hashSizeBytes*8)/2 - (witnessSize)/2)

        workEq, qfEq, qgEq = PredictedCostEq(c, z, wSize, tSize)
        xEq.append(witnessSize)
        yEq.append(workEq)

        # for sample in range(numSamplesPerT):
        #     print("on sample", sample, "for witnessSize", witnessSize, "c", c)
        #     workReal = run(c, z, wSize, tSize)
        #     samples.append(workReal)
        #     xSamples.append(witnessSize)
            
        #     # These are global counters, we need to reset them after each run
        #     # This is a bit of a hack and somewhat dangerous. Not worth fixing for this one off task
        #     global dInternalCount
        #     dInternalCount = 0
        #     global hCount
        #     hCount = 0

    # We save the previous run outputs here so we don't have to rerun the lengthy computation when tweaking the graph
    # previous run 40 bits (every second position) 1 sample per t
    # xSamples = [20, 22, 24, 26, 28, 30, 32, 34, 36, 38] 
    # samples = [26.947433806132818, 25.875842956737074, 25.538076889852594, 22.25777281664073, 24.646882879160493, 21.948300208319182, 23.085003133767923, 24.45109411957593, 24.09847743170647, 24.3310476559132]

    # previous run 40 bits (every second position) 5 sample per t
    xSamples = [20, 20, 20, 20, 20, 22, 22, 22, 22, 22, 24, 24, 24, 24, 24, 26, 26, 26, 26, 26, 28, 28, 28, 28, 28, 30, 30, 30, 30, 30, 32, 32, 32, 32, 32, 34, 34, 34, 34, 34, 36, 36, 36, 36, 36, 38, 38, 38, 38, 38] 
    samples = [26.33466376815708, 27.036121438953128, 25.59484700197138, 27.094771949608464, 26.224680628457957, 25.093548532873772, 25.45931250791735, 25.76053133985475, 25.300569783838938, 22.330657611803698, 24.273092053662165, 25.91272796894369, 25.23849286464406, 25.46985246969138, 22.368451043001894, 20.884854670918266, 23.280432242015085, 22.97073048142575, 22.567615184110863, 22.588780046472205, 23.982940497016838, 24.31412827296044, 24.299155114461932, 24.931813626330303, 24.092866157422208, 25.031674830128342, 24.003486772943948, 23.91372415676553, 22.904001514846613, 24.305291801634173, 23.668132966355245, 23.233622894717207, 23.997696862747453, 24.37435306146796, 22.32186562943628, 24.392566956213493, 25.46406831663872, 24.472767986104035, 23.503675211685316, 24.540066120727058, 23.750589540551164, 24.959134027566428, 24.81202640896024, 24.049309734283607, 25.053889474463993, 24.51789293230533, 24.723639125738714, 24.79734241443696, 24.52647900124225, 24.148820925808156]
    
    import matplotlib.pyplot as plt

    # Create the plot
    fig = plt.figure(figsize=(5, 4))

    print(xEq, yEq)
    print(xSamples, samples)
    plt.plot(xSamples, samples, marker='o', linestyle='none', color="black", alpha=0.1, label='Actual')
    plt.plot(xEq, yEq, color='red', marker='.', linestyle=':', label='Predicted')
    plt.yticks([15, 20, 25, 30, 35])
    plt.xticks([witnessSize for witnessSize in range(20, round(hashSizeBytes*8)-1, 1)])

    # Labels
    plt.xlabel("Equivalence witness size $||\omega||+||t||$")
    plt.ylabel("Hash Queries (log2)")
    plt.title("Predicted vs. actual truncated col.")
    plt.legend()
    plt.show()

    fig.savefig('figures/actualvspredictedgraph.png', dpi=fig.dpi)


def main():
    # Uncomment to run tests
    # test()
    graph()

if __name__ == "__main__":
    main()


