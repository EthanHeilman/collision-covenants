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

    numSamplesPerT = 25
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

        for sample in range(numSamplesPerT):
            print("on sample", sample, "for witnessSize", witnessSize, "c", c)
            workReal = run(c, z, wSize, tSize)
            samples.append(workReal)
            xSamples.append(witnessSize)
            
            # These are global counters, we need to reset them after each run
            # This is a bit of a hack and somewhat dangerous. Not worth fixing for this one off task
            global dInternalCount
            dInternalCount = 0
            global hCount
            hCount = 0

    # We save the previous run outputs here so we don't have to rerun the lengthy computation when tweaking the graph
    # previous run 40 bits (every second position) 1 sample per t
    # xSamples = [20, 22, 24, 26, 28, 30, 32, 34, 36, 38] 
    # samples = [26.947433806132818, 25.875842956737074, 25.538076889852594, 22.25777281664073, 24.646882879160493, 21.948300208319182, 23.085003133767923, 24.45109411957593, 24.09847743170647, 24.3310476559132]

    # previous run 40 bits (every second position) 5 sample per t
    # xSamples = [20, 20, 20, 20, 20, 22, 22, 22, 22, 22, 24, 24, 24, 24, 24, 26, 26, 26, 26, 26, 28, 28, 28, 28, 28, 30, 30, 30, 30, 30, 32, 32, 32, 32, 32, 34, 34, 34, 34, 34, 36, 36, 36, 36, 36, 38, 38, 38, 38, 38] 
    # samples = [26.33466376815708, 27.036121438953128, 25.59484700197138, 27.094771949608464, 26.224680628457957, 25.093548532873772, 25.45931250791735, 25.76053133985475, 25.300569783838938, 22.330657611803698, 24.273092053662165, 25.91272796894369, 25.23849286464406, 25.46985246969138, 22.368451043001894, 20.884854670918266, 23.280432242015085, 22.97073048142575, 22.567615184110863, 22.588780046472205, 23.982940497016838, 24.31412827296044, 24.299155114461932, 24.931813626330303, 24.092866157422208, 25.031674830128342, 24.003486772943948, 23.91372415676553, 22.904001514846613, 24.305291801634173, 23.668132966355245, 23.233622894717207, 23.997696862747453, 24.37435306146796, 22.32186562943628, 24.392566956213493, 25.46406831663872, 24.472767986104035, 23.503675211685316, 24.540066120727058, 23.750589540551164, 24.959134027566428, 24.81202640896024, 24.049309734283607, 25.053889474463993, 24.51789293230533, 24.723639125738714, 24.79734241443696, 24.52647900124225, 24.148820925808156]
    
    # previous run 40 bits (every second position) 20 sample per t
    # xSamples = [20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 36, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38, 38]
    # samples = [26.31650167000893, 26.841679342650675, 26.774317468977195, 25.687648046539696, 26.364841962371553, 25.887669236277908, 26.52197211023208, 27.21952279354002, 26.64141743821282, 26.14299983912189, 27.386367863955208, 27.312198340861112, 26.383544584870215, 25.182982732582154, 25.52633398454383, 25.740193431364823, 27.491368910680205, 27.00979977070159, 27.40786722338409, 26.059884801000358, 26.05194811158582, 25.528838622507912, 25.66195740380907, 24.715978114407672, 22.839501952669814, 24.51974079951103, 26.061860027939776, 26.48231849400841, 25.50494130815545, 24.45904469960195, 25.57322623533716, 25.20094083646254, 24.02325224180138, 26.13501158392043, 24.515893197731504, 24.983151403988362, 24.64573785571835, 25.475334159543934, 25.14552352153949, 24.549265466413686, 24.192864532610777, 26.42160622266052, 21.559291658778122, 26.90735165327708, 24.878891449152917, 24.46603176393879, 25.712989687889134, 25.427797002083693, 23.530015960184844, 22.246093701328803, 25.98365124956839, 26.07853879678384, 24.93046110134271, 23.006363577445807, 25.536712676435663, 25.753163971261795, 25.245212957735543, 22.446059506192853, 25.579749385643623, 22.008873103699575, 21.690556043362896, 23.285303294577826, 21.758155290704774, 23.237282329011432, 23.72218444576, 24.2323855729427, 23.824473336352966, 23.748334038037175, 22.120887108060586, 22.87249979259214, 22.486386515061998, 21.291525968163164, 22.848750719745386, 21.612243091701085, 20.424162187263867, 20.469624926455246, 23.095828862870867, 22.942955071596774, 22.01467434851541, 22.83181402748685, 17.924081787242255, 23.78533372606018, 23.856449085789272, 24.864290163097543, 22.253779981696702, 25.554867831790684, 24.78794972388972, 25.02418957259665, 22.766454095193257, 21.940782072885003, 25.234143268336208, 25.487225049938043, 24.867299056352223, 24.51848375817526, 24.528047044347023, 25.242607907609564, 22.341720233145406, 23.801995631715485, 23.986789477451193, 24.84412699358014, 23.694053036576836, 23.883223126402925, 24.611994035066132, 23.24945000540693, 23.925669880267147, 23.572996334187355, 25.16964987940644, 24.35249966375388, 24.061439756175663, 23.085564360996788, 24.14308997855747, 24.981710941333652, 24.277581833207293, 23.52105439467368, 22.712423513598832, 24.331306100324714, 23.58747252387446, 23.572372598813367, 25.184531062304124, 25.11978859179712, 23.255809469298615, 24.157795006178976, 23.260141396001792, 22.999880983096514, 23.738072565660083, 23.363111436515, 25.353582894968202, 23.252029274432303, 23.013066536821643, 22.824620072061023, 23.827356951937272, 22.690878467056713, 23.62307046307232, 22.045721339819867, 23.828453796451278, 24.511765681040977, 23.176935686001002, 25.004083489952325, 23.162630886402077, 24.017442213231906, 24.205750376878335, 24.337028258440665, 21.850423412712296, 23.51238819933187, 24.61864465902348, 24.16478734164316, 25.28076546133161, 24.328739837416023, 23.072839979966975, 24.653613637038134, 23.301413719448757, 22.79081340854049, 24.12599355587187, 25.50093770999722, 24.331528963761322, 24.2515321800454, 25.11348183160837, 23.472300518235492, 24.631859182776786, 23.60277145911455, 25.76275010472803, 23.98596150985515, 24.818618305955326, 24.937366276439793, 24.027223745494208, 23.887128931091993, 24.983714628532336, 25.09145830791356, 24.042038640998708, 24.06887739807822, 24.911601914988104, 23.743439779189554, 25.17334107731379, 23.20676309538189, 25.082174669714327, 25.32426238335548, 24.259674311869706, 23.61789192828106, 23.857086787825686, 23.197177240277874, 23.82703949526134, 23.87590586453272, 24.271618469583377, 24.09480949344388, 25.551703187149645, 24.429427047047138, 24.47008165318364, 23.698188747444167, 23.961047075309978, 23.3890375752866, 23.532336542330672, 23.702600318265155, 23.91729130690657, 24.57029784371503, 24.266067983546936, 24.29525473260882, 24.44281583558393, 24.644046156182743, 24.192363106330564, 24.221227628705723]

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


