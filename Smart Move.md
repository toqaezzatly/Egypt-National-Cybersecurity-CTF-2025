This is a comprehensive write-up for the **Smart Move** cryptography challenge. You can use this for your blog, GitHub, or internal documentation.

---

# Write-up: Smart Move (Crypto Challenge)

## 1. Challenge Overview
*   **Name:** Smart Move
*   **Category:** Cryptography
*   **Theme:** Elliptic Curve Cryptography (ECC)
*   **Hint:** "They say cryptographers are smart..."
*   **Provided Files:** 
    *   `script.sage`: The source code used to generate the challenge.
    *   `output.txt`: Contains the prime $p$, curve parameters $a_1, a_2$, and the points $S$ and $T$.

## 2. Analysis
Looking at the provided `script.sage`, we see that the challenge generates a prime $p$ and an elliptic curve defined over the ring $\mathbb{Z}/p^3$. It then picks a point $S$ and calculates $T = m \cdot S$, where $m$ is the byte-encoded flag.

The key hint lies in the name **"Smart Move."** In ECC, **Smart's Attack** is a well-known method used to solve the Discrete Logarithm Problem (DLP) on **Anomalous Curves**.

### What is an Anomalous Curve?
An elliptic curve $E(\mathbb{F}_p)$ is anomalous if the number of points on the curve is exactly equal to $p$ (i.e., the trace of Frobenius is 1). On such curves, the Discrete Logarithm Problem is not hard; it can be solved in polynomial time.

### The Attack Logic
While the standard Smart's Attack works on curves over $\mathbb{F}_p$ by lifting them to $p$-adic numbers, this challenge gives us a curve already defined over $\mathbb{Z}/p^3$. 

1.  **The Kernel:** By multiplying our points by the order of the curve $n$ (which is $p$), we "push" the points into the kernel of the reduction map, denoted as $E_1(p)$.
2.  **Linearization:** For points in this kernel, the elliptic curve group law becomes isomorphic to the additive group $(\mathbb{Z}/p^k, +)$. 
3.  **The Coordinate:** We map a point $P = (x, y)$ to a linear coordinate $t$ using the formula:
    $$t(P) = -\frac{x}{y} \pmod{p^k}$$
4.  **Solving:** The relationship $T = m \cdot S$ becomes a simple linear equation:
    $$t(T_{kernel}) \equiv m \cdot t(S_{kernel}) \pmod{p^k}$$
    Because the flag is 40 bytes (320 bits) and $p$ is 256 bits, we solve this modulo $p^2$ to recover the full flag.

## 3. Implementation (SageMath)

We use the following script to perform the "lifting" and solve the linear equation:

```python
# 1. Load Data
p = 77850376203167082774832332184672896189931422848651278014948748677228456332131
a1 = 54218396295747723814424256150888176111221178301395281945102353539212737911035
a2 = 61218013219285849474796901019700888900813809664160179992304043263572452193336

Sx = 241180723497442482330367812582158547743446031776411113595405872566221794395256582184317280589879202035747732151779161499088366825422670793341162618889792751454990293203892248035092010213533424623465860626349538834411761549474342149
Sy = 168462652779133703946945260758649348241725210242169399013006152879583714553723743677100213164655979332546294444972092078974924892370533483883586638331254934669888229119561379369430441788648163141949755262983975554131442146136973484

Tx = 424851916228714462365085257292763894061382284875782003631369845562693655809234282909562260797914837320564563093335974827930050357413049537501422911381381898645035029588295205598189406116072282929695864693916579869541203622715096376
Ty = 105754228565087023376118142239483499795342624795650260177891063513111144610927604886831720337269741987729635922298201611139539479287046924868964291424924768695000710410719796294206815492445391996206582430136842447279551532585811588

# 2. Setup Curve over Z/p^3
R = Zmod(p^3)
E = EllipticCurve(R, [a1, a2])
S = E(Sx, Sy)
T = E(Tx, Ty)

# 3. Find the order of the curve over the base field Fp
# (Confirming n = p for anomalous curve)
E_base = EllipticCurve(GF(p), [a1, a2])
n = E_base.order()

# 4. Map to the formal group by multiplying by n
Sk = n * S
Tk = n * T

# 5. Extract linear parameter t = -x/y
def get_t(P, prime):
    return (-int(P[0]) * pow(int(P[1]), -1, prime^3)) % (prime^3)

ts = get_t(Sk, p)
tt = get_t(Tk, p)

# 6. Solve tt = m * ts (mod p^3)
# Divide by p to solve in p^2 for full flag recovery
m = (int(tt) // p * pow(int(ts) // p, -1, p^2)) % (p^2)

# 7. Reveal Flag
print(int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big').decode())
```

## 4. Final Flag
After running the script in SageMath, the Discrete Logarithm is solved, and the flag is revealed:
<img width="1840" height="975" alt="image" src="https://github.com/user-attachments/assets/c5e89180-1a0e-4f56-95c6-72803474f25d" />


**`FLAG{SM@RT_@TT@K_1s_@SM@RT_M0V3_1snt_1t}`**

## 5. Conclusion
This challenge demonstrates that Elliptic Curves are not inherently secure if their parameters are chosen poorly. By using an anomalous curve and working over an extension ring $\mathbb{Z}/p^k$, the challenge designer created a perfect environment for a $p$-adic attack (Smart's Attack), reducing a hard cryptographic problem to simple modular arithmetic.
