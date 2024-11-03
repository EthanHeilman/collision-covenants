import math
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from matplotlib.offsetbox import AnnotationBbox, TextArea

# Constants
blake3Cost = 45000
sha256Cost = 218000

# Computes the cost of our B3 Merkle tree
def b3MerkleCost(widthLog2):
    treeRadix = 4
    depth = math.ceil( math.log((2**widthLog2/3), treeRadix)+1)

    b3TruncatedOut = 128/8

    # Determines how many levels of the tree we can cut off before it costs us more space than it saves us
    treeTopCutLength = 0
    for i in range(1,depth):
        if (treeRadix**i)*b3TruncatedOut > blake3Cost:
            break
        else:
            treeTopCutLength = i

    treeTopCost = 4**(treeTopCutLength)*(b3TruncatedOut)

    # The actual value is 16,384, but we approximate it in the paper to 17,000
    # I consider this fair to do because it makes the overestimates the cost.
    if treeTopCost == 16384.0:
        treeTopCost = 17000

    b3Calls = depth-treeTopCutLength
    pushObjects = (b3Calls-1)*((treeRadix-1)*b3TruncatedOut/4)
    totalCost = treeTopCost + b3Calls*blake3Cost
    return totalCost, pushObjects


# Given a hash size and a merkle tree size, find the cost of the covenant
def findBudget(hashSize, mkSizeLog2):
    sha1Cost = hashSize
    ripemdCost = hashSize
    txDataCost = 0 # in bytes

    covenantCost = 2*sha256Cost+ripemdCost+txDataCost

    # We hardcode the witness size parameters here
    wSize = 33
    tSize = 70

    dGenCalls =  wSize + tSize - mkSizeLog2
    # min(sha1Cost, ripemdCost) here is exploiting the trick that we can use the identity or a hash function call for the last bit of the witness
    dGenCallsCost = (dGenCalls-1)*(sha1Cost+ripemdCost)+(min(sha1Cost, ripemdCost)) 
    dGenPushObjects = (wSize + tSize)/(8)/4

    b3Cost, b3PushObjects = b3MerkleCost(mkSizeLog2)

    pushObjects = math.ceil(txDataCost/4 + b3PushObjects + dGenPushObjects)
    totalByteCost = covenantCost + b3Cost + dGenCallsCost
    # print(f"pushObjects: {pushObjects}, hashSize: {hashSize}, totalByteCost: {totalByteCost}, b3Cost: {b3Cost} dGenCalls: {dGenCalls}, dGenCallsCost: {dGenCallsCost} covenantCost: {covenantCost}")
    return totalByteCost

# Size a Merkle tree size (u) determines the maximum size of the script size implementation of SHA-1 and RIPEMD-160 can be
def MinCostPerU():
    yValues = []
    start = 80 
    stop = 101
    # mkSizeLogs = The number of bits of the equivalent witness size to commit to in the merkle true
    for mkSizeLog2 in range(start, stop, 1):
        hashSize = 0
        smallScriptSize = 0
        while True:
            smallScriptSize = findBudget(hashSize, mkSizeLog2)
            if smallScriptSize > 4*1000*1000:
                break
            hashSize = hashSize + 1

        # We just made a transaction that is too big, so the previous value must be the largest allowable
        hashSize = hashSize - 1
        smallScriptSize = findBudget(hashSize, mkSizeLog2)
        yValues.append(hashSize*2)
        
        print(mkSizeLog2, hashSize*2, smallScriptSize)
    return np.arange(start, stop), yValues


# This is used to find the optimal parameters (wSize, tSize, z) for the covenant given a limit on the size of the distinguished points table (dpSizeLimitLog2)
# Much of this logic is reused by SpendCostByWitnessSize
def findParams():
    dpSizeLimitLog2 = 56

    leastTime = -1
    leastTimeParams = ""

    for z in range(1, 35, 1):
        for qf in range(70, 80, 1):
            dpSizeLog2 = math.log2((20-z/8)*(2**(qf-z) + 2**(160-qf-z)))
            if dpSizeLog2 > dpSizeLimitLog2:
                continue
            for wSize in range(33, 34, 1):
                for tSize in range(97-wSize, 104-wSize, 1):
                    timeLog2 = math.log2(2**(qf+math.log2(tSize))+2**(160-qf) + 2**(2*qf+math.log2(tSize)+z-wSize-tSize-1) + 2**(2*(160-qf)+z-160-1))

                    if leastTime == -1 or timeLog2 < leastTime:
                        leastTime = timeLog2
                        leastTimeParams = f'z={z},qf={qf},tSize+wSize={tSize+wSize},tSize={tSize},wSize={wSize},timeBits={timeLog2},spaceBytes={dpSizeLog2}'

    print(leastTimeParams)

# Computes the work in terms of hash queries for an attacker to break the covenant
def SecurityByWitnessSize():
    yValues=[]
    start = 80
    stop = 161
    for witnessSize in range(start, stop, 1):
        wSize = 33
        tSize = witnessSize - wSize
        workReqLog2List = []

        # Rather solve this symbolically, we brute force it as this is less like to result in a mistake and computers are fast
        # "Brute force the king of approaches, the approach of kings"
        precision = 1000
        for stepOneWorkLog2 in range(start*precision, stop*precision, 1):
            stepOneWorkLog2Float = float(stepOneWorkLog2)/precision

            # Plus 1 for covenant since half the collisions used by the covenant will be not useful to the attacker
            expColPairsLog2 = 2*stepOneWorkLog2Float-(161+1)
            # For equivalence uncomment this instead: 
            # expColPairsLog2 = 2*stepOneWorkLog2Float-(161)

            # If this is true, then we have less than 1/2 change of breaking the covenant so continue
            if 159 - expColPairsLog2 >= witnessSize:
                continue

            stepTwoWorkLog2 = (159 - expColPairsLog2) + math.log2(tSize)
            totalWorkLog2 = math.log2(2**stepOneWorkLog2Float + 2**stepTwoWorkLog2)

            workTuple = (totalWorkLog2, stepOneWorkLog2Float, (159 - expColPairsLog2), stepTwoWorkLog2)
            workReqLog2List.append(workTuple)
        print(witnessSize, min(workReqLog2List, key=lambda x: x[0]))
        yValues.append(min(workReqLog2List)[0])

    xValues = np.arange(start, stop)
    return xValues, yValues

# Computes the work in terms of hash queries for an honest party to spend the covenant
def SpendCostByWitnessSize(spaceLimit):
    yValues=[]
    start = 80
    stop = 161
    for witnessSize in range(start, stop, 1):
        wSize = 33
        tSize = witnessSize - wSize
        log2Tsize = math.log2(tSize)
        workReqLog2List = []
        
        # We just brute force this, rather have solve it logically
        # Number of queries to f
        for qfLog2 in range(70, 90, 1):
            for z in range(1, 60, 1):
                workLog2 = math.log2(
                    2**(qfLog2 + log2Tsize) 
                    + 2**(160-qfLog2) 
                    + 2**(2*qfLog2+log2Tsize+z-wSize-tSize-1) 
                    + 2**(2*(160-qfLog2)+z-160-1))
                space = math.log2((20-z/8)*(2**(qfLog2-z) + 2**(160-qfLog2-z)))
                if space > spaceLimit:
                    continue
                workTuple = (workLog2, space, qfLog2, z, log2Tsize)
                workReqLog2List.append(workTuple)

        # we want the least work
        print(witnessSize, min(workReqLog2List, key=lambda x: x[0]))
        yValues.append(min(workReqLog2List)[0])

    xValues = np.arange(start, stop)
    return xValues, yValues


def GraphBothFigures():
    # ChatGPT was used to generate some of this code as malplotlib makes annotations tricky but ChatGPT is excellent at it.

    # Attacker cost
    xSecurity, ySecurity = SecurityByWitnessSize()

    # Honest spend code For different space limits
    xCost1, yCost1 = SpendCostByWitnessSize(48)
    xCost2, yCost2 = SpendCostByWitnessSize(56)
    xCost3, yCost3 = SpendCostByWitnessSize(64)
    xCost4, yCost4 = SpendCostByWitnessSize(80)
    
    fig, (pltleft, pltright) = plt.subplots(1, 2, figsize=(12, 5), gridspec_kw={'width_ratios': [1, 2]})
    
    # Annotate y-values for each line on the right plot at x = 103 with lines to the axes
    x_annotate = 103
    datasets = [
        (xSecurity, ySecurity, 'Attacker with infinite space', 'grey'),
        (xCost2, yCost2, 'Honest with space $<2^{56}$ (bytes)', 'grey'),
    ]

    for x_data, y_data, label, color in datasets:
        if x_annotate in x_data:
            y_value = y_data[np.where(x_data == x_annotate)[0][0]]

            # Draw vertical and horizontal lines from the point to the axes
            pltright.axvline(x=x_annotate, color=color, linestyle='--', linewidth=1.2)
            pltright.axhline(y=y_value, color=color, linestyle='--', linewidth=1.2)

    # Plot for the right figure
    pltright.plot(xSecurity, ySecurity, color='red', marker='$\mathsf{A}$', linestyle='none', label='Attacker with infinite space')
    pltright.plot(xCost4, yCost4, color='purple', fillstyle='none', label='Honest with space $<2^{80}$ (bytes)')
    pltright.plot(xCost3, yCost3, marker='o', linestyle='none', fillstyle='none', label='Honest with space $<2^{64}$ (bytes)')
    pltright.plot(xCost2, yCost2, marker='x', color='green', linestyle='none', label='Honest with space $<2^{56}$ (bytes)')
    pltright.plot(xCost1, yCost1, marker='>', linestyle='none', fillstyle='none', label='Honest with space $<2^{48}$ (bytes)')

    pltright.set_title('Equivalence witness size vs queries needed')
    pltright.set_xlabel('Equivalence Witness Size ($||\omega||+||t||$ bits)')
    pltright.set_ylabel('Queries needed ($log_2$)')
    pltright.legend()
    pltright.grid(True)

    # Add a specific y-axis tick at y for x = 103 in (xCost2, yCost2)
    x_target = 103
    if x_target in xCost2:
        y_target = yCost2[np.where(xCost2 == x_target)[0][0]]

        # Add y_target to y-ticks if not already included
        current_yticks = pltright.get_yticks().tolist()

        # Move the label for y_target slightly upward using AnnotationBbox
        offsetbox = TextArea(f'{y_target:,.0f}', textprops=dict(ha='center', va='bottom', fontsize=10))
        annotation = AnnotationBbox(offsetbox, (0, y_target), xybox=(-13, 2), xycoords=('axes fraction', 'data'),
                                    boxcoords="offset points", frameon=False)
        pltright.add_artist(annotation)

    # Plot for the left figure
    xU, yU = MinCostPerU()
    pltleft.plot(xU, yU, marker='o', linestyle=':')
    pltleft.set_title('Pre-comp. for < 4MB txn')
    pltleft.set_xlabel('u - Merkle tree size ($log_2$)')
    pltleft.set_ylabel('(||SHA-1||+||RIPEMD||) implementation size (opcodes)')
    pltleft.grid(True)

    # Highlight the point at x = 90 on the left plot with neon purple lines and formatted ticks
    x_highlight = 90
    idx = np.where(xU == x_highlight)[0]
    if idx.size > 0:
        y_highlight = yU[idx[0]]  # Get the corresponding y value for x = 90
        
        pltleft.axvline(x=x_highlight, color='grey', linestyle='--', linewidth=1.5)
        pltleft.axhline(y=y_highlight, color='grey', linestyle='--', linewidth=1.5)

        # Add custom ticks on both axes
        current_xticks = pltleft.get_xticks().tolist()
        if x_highlight not in current_xticks:
            current_xticks.append(x_highlight)
            pltleft.set_xticks(current_xticks)
        
        current_yticks = pltleft.get_yticks().tolist()
        if y_highlight not in current_yticks:
            current_yticks.append(y_highlight)
            pltleft.set_yticks(current_yticks)

        # Format ticks with commas
        pltleft.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f'{int(x):,}'))
        pltleft.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f'{int(y):,}'))

    fig.savefig('figures/covcolgraph.png', dpi=fig.dpi)
    
    plt.show()


if __name__ == "__main__":
    GraphBothFigures()
