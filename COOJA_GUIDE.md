# Complete Cooja GUI Simulation Guide
## Post-Quantum Cryptography Implementation

**Goal**: Run Ring-LWE authentication + LDPC encryption simulation in Cooja GUI

---

## 📋 Prerequisites Checklist

Before starting, ensure you have:

- [x] Contiki-NG installed at `C:\contiki-ng`
- [x] Apache Ant installed (for running Cooja)
- [x] Java JDK 8 or higher installed
- [x] Project files in `C:\Users\aloob\Desktop\My_Research`
- [x] Z1 firmware compiled: `make TARGET=z1`

---

## 🔧 Step 1: Compile Firmware for Z1 Mote

### 1.1 Open Terminal/PowerShell

Navigate to your project directory:

```powershell
cd C:\Users\aloob\Desktop\My_Research
```

### 1.2 Compile for Z1 Target

```powershell
make TARGET=z1
```

**Expected Output**:
```
  CC        crypto_core.c
  CC        node-sender.c
  CC        node-gateway.c
  LD        build/z1/node-sender.z1
  LD        build/z1/node-gateway.z1
```

### 1.3 Verify Files Created

```powershell
ls build\z1\*.z1
```

You should see:
- `build/z1/node-gateway.z1`
- `build/z1/node-sender.z1`

**✅ Checkpoint**: If compilation succeeds, proceed to Step 2. If errors occur, check `RUN_INSTRUCTIONS.md` troubleshooting section.

---

## 🚀 Step 2: Start Cooja Simulator

### 2.1 Navigate to Cooja Directory

```powershell
cd C:\contiki-ng\tools\cooja
```

### 2.2 Launch Cooja

```powershell
ant run
```

**What happens**:
- Ant will compile Cooja (first time may take 1-2 minutes)
- Cooja GUI window will open

**If ant command not found**:
```powershell
# Install Apache Ant first
choco install ant
# OR download from: https://ant.apache.org/bindownload.cgi
```

### 2.3 Wait for Cooja Window

You should see:
```
Buildfile: C:\contiki-ng\tools\cooja\build.xml
...
[java] Cooja: Starting Java side...
```

The **Cooja Simulator** window will appear with menu bar.

---

## 📂 Step 3: Load Simulation Configuration

### Option A: Load Pre-Made Simulation (Recommended)

**3.1** In Cooja menu bar: **File → Open Simulation...**

**3.2** Navigate to:
```
C:\Users\aloob\Desktop\My_Research\simulation.csc
```

**3.3** Click **Open**

**3.4** Cooja will ask about firmware paths. Click **Yes** or **Update paths**

**3.5** Browse to firmware files:
- Gateway firmware: `C:\Users\aloob\Desktop\My_Research\build\z1\node-gateway.z1`
- Sender firmware: `C:\Users\aloob\Desktop\My_Research\build\z1\node-sender.z1`

**✅ Skip to Step 4** (simulation is now loaded)

---

### Option B: Create New Simulation (Manual Setup)

Follow this if `simulation.csc` doesn't load properly.

#### 3B.1 Create New Simulation

1. **File → New Simulation**
2. Enter simulation name: `Post-Quantum IoT Crypto`
3. Click **Create**

#### 3B.2 Add Gateway Mote

1. In the **Network** panel, click **Add Motes**
2. Select **Z1 mote**
3. Click **Browse** next to "Contiki process / Firmware"
4. Navigate to: `C:\Users\aloob\Desktop\My_Research\build\z1\node-gateway.z1`
5. Click **Open**
6. Set **Number of motes**: `1`
7. Click **Add motes**
8. Click **Close**

#### 3B.3 Add Sender Mote

1. Click **Add Motes** again
2. Select **Z1 mote**
3. Click **Browse**
4. Navigate to: `C:\Users\aloob\Desktop\My_Research\build\z1\node-sender.z1`
5. Click **Open**
6. Set **Number of motes**: `1`
7. Click **Add motes**
8. Click **Close**

#### 3B.4 Position Motes

In the **Network** visualization panel:

1. **Drag Gateway mote** (ID 1) to the **left side**
2. **Drag Sender mote** (ID 2) to the **right side**
3. Keep them within **50 meters** (visible distance in grid)

**Recommended positions**:
- Gateway: X=0, Y=0, Z=0
- Sender: X=30, Y=0, Z=0

#### 3B.5 Configure Radio Medium

1. Go to **Settings → Radio Medium**
2. Select **Unit Disk Graph Medium (UDGM)**
3. Set parameters:
   - **Transmission range**: 50 meters
   - **Interference range**: 100 meters
   - **Success ratio TX**: 1.0
   - **Success ratio RX**: 1.0
4. Click **OK**

---

## 🎮 Step 4: Open Essential Windows

To monitor the simulation, open these windows:

### 4.1 Mote Output Window (CRITICAL)

**Purpose**: View console logs from both nodes

**How to open**:
1. **Tools → Mote Output**
2. A new window appears showing real-time logs
3. Keep this window visible during simulation

**What you'll see**:
```
ID:1 [INFO: Gateway] === Post-Quantum Gateway Node Starting ===
ID:2 [INFO: Sender] === Post-Quantum Sender Node Starting ===
```

### 4.2 Timeline Window (Optional but Recommended)

**Purpose**: Visualize packet transmission timing

**How to open**:
1. **Tools → Timeline**
2. Check these options:
   - ✅ Radio messages
   - ✅ Radio HW
   - ✅ Log output

### 4.3 Radio Messages Window (Optional)

**Purpose**: See UDP packets being exchanged

**How to open**:
1. **Tools → Radio Messages**
2. Shows all packets: AUTH, ACK, DATA

---

## ▶️ Step 5: Run the Simulation

### 5.1 Start Simulation

Click the **Start** button (green play icon) in the **Simulation Control** panel

**OR**

Press `Ctrl + S`

### 5.2 Set Speed (Optional)

In **Simulation Control** panel:
- **Speed limit**: 100% is real-time
- Increase to **500%** or **1000%** to speed up simulation
- Use **No speed limit** for maximum speed (be careful with output window)

### 5.3 Watch the Protocol Execute

The **Mote Output** window will show the protocol phases:

---

## 📊 Step 6: Expected Output Log

### Phase 1: Gateway Initialization (ID:1)

```
ID:1 [INFO: Gateway] === Post-Quantum Gateway Node Starting ===
ID:1 [INFO: Gateway] Implementing Kumari et al. LR-IoTA + QC-LDPC

ID:1 [INFO: Gateway] [Initialization] Generating cryptographic keys...

ID:1 [INFO: Gateway] 1. Generating Ring-LWE keys...
ID:1 [INFO: Gateway]    Ring-LWE key generation: SUCCESS
ID:1 [INFO: Gateway] 2. Generating QC-LDPC keys...
ID:1 [INFO: Gateway]    LDPC matrix generation: SUCCESS
ID:1 [INFO: Gateway]    Matrix size: 408x816
ID:1 [INFO: Gateway]    Row weight: 6, Column weight: 3
ID:1 [INFO: Gateway] 3. Initializing ring member public keys...
ID:1 [INFO: Gateway]    Ring setup complete (3 members)

ID:1 [INFO: Gateway] === Gateway Ready ===
ID:1 [INFO: Gateway] Configuration:
ID:1 [INFO: Gateway]   - Polynomial degree (n): 512
ID:1 [INFO: Gateway]   - Modulus (q): 536870909
ID:1 [INFO: Gateway]   - Standard deviation (σ): 43
ID:1 [INFO: Gateway]   - Ring size (N): 3
ID:1 [INFO: Gateway]   - LDPC dimensions: 408x816

ID:1 [INFO: Gateway] Listening for incoming connections on UDP port 5678...
```

### Phase 2: Sender Initialization (ID:2)

```
ID:2 [INFO: Sender] === Post-Quantum Sender Node Starting ===
ID:2 [INFO: Sender] Implementing Kumari et al. LR-IoTA + QC-LDPC

ID:2 [INFO: Sender] [Phase 1] Generating Ring-LWE keys...
ID:2 [INFO: Sender] Ring-LWE key generation successful
ID:2 [INFO: Sender]   - Secret key generated
ID:2 [INFO: Sender]   - Public key generated
ID:2 [INFO: Sender]   - Random polynomial R generated
ID:2 [INFO: Sender] Generating public keys for other ring members...
ID:2 [INFO: Sender]   - Ring member 2 public key generated
ID:2 [INFO: Sender]   - Ring member 3 public key generated
```

### Phase 3: Authentication (Ring Signature)

```
ID:2 [INFO: Sender] [Phase 2] Starting Ring Signature Authentication...
ID:2 [INFO: Sender] Keyword: AUTH_REQUEST
ID:2 [INFO: Sender] Generating ring signature (N=3 members)...
ID:2 [INFO: Sender] Ring signature generated successfully
ID:2 [INFO: Sender]   - Signature components: S1, S2, S3
ID:2 [INFO: Sender]   - Real signer hidden among 3 members
ID:2 [INFO: Sender] Sending authentication packet to gateway...
ID:2 [INFO: Sender] Authentication packet sent!
ID:2 [INFO: Sender] Waiting for gateway verification...
```

**Gateway receives and verifies**:
```
ID:1 [INFO: Gateway] Received message type 0x01 from fe80::202:2:2:2

ID:1 [INFO: Gateway] [Authentication Phase] Received ring signature
ID:1 [INFO: Gateway] Keyword: AUTH_REQUEST
ID:1 [INFO: Gateway] Verifying ring signature...
ID:1 [INFO: Gateway] *** SIGNATURE VALID ***
ID:1 [INFO: Gateway] Ring signature verification successful!
ID:1 [INFO: Gateway] Sender authenticated (anonymous among 3 members)
ID:1 [INFO: Gateway] Sending ACK with LDPC public key to sender...
ID:1 [INFO: Gateway] ACK sent! Waiting for encrypted data...
```

### Phase 4: Key Exchange (ACK with LDPC Public Key)

```
ID:2 [INFO: Sender] Received message type 0x02 from fe80::201:1:1:1
ID:2 [INFO: Sender] Authentication ACK received! Gateway authenticated us.
ID:2 [INFO: Sender] Received Gateway's LDPC public key
ID:2 [INFO: Sender] Proceeding to encrypted data transmission...
```

### Phase 5: Hybrid Encryption & Data Transfer

```
ID:2 [INFO: Sender] Encrypted message 'Hello IoT' (10 bytes)
ID:2 [INFO: Sender] Sending encrypted data to gateway...
ID:2 [INFO: Sender] Data transmission complete!

ID:2 [INFO: Sender] === PROTOCOL COMPLETE ===
ID:2 [INFO: Sender] Successfully authenticated and encrypted message sent!
```

### Phase 6: Decryption (The Finale!)

```
ID:1 [INFO: Gateway] Received message type 0x03 from fe80::202:2:2:2

ID:1 [INFO: Gateway] [Data Phase] Received encrypted message
ID:1 [INFO: Gateway] Syndrome size: 51 bytes
ID:1 [INFO: Gateway] Ciphertext size: 10 bytes
ID:1 [INFO: Gateway] Decoding LDPC syndrome to recover error vector...
ID:1 [INFO: Gateway] LDPC decoding successful!
ID:1 [INFO: Gateway] Session key derived from error vector
ID:1 [INFO: Gateway] AES decryption complete

ID:1 [INFO: Gateway] ========================================
ID:1 [INFO: Gateway] *** DECRYPTED MESSAGE: Hello IoT ***
ID:1 [INFO: Gateway] ========================================

ID:1 [INFO: Gateway] Protocol execution successful!
```

**🎉 SUCCESS!** If you see the decrypted message, the simulation worked perfectly!

---

## 🎥 Step 7: Visualization & Analysis

### 7.1 Timeline View

In the **Timeline** window, you should see:

1. **Radio transmission spikes** at specific times:
   - First spike: AUTH packet (sender → gateway)
   - Second spike: ACK packet (gateway → sender)
   - Third spike: DATA packet (sender → gateway)

2. **Color coding**:
   - Green bars: Radio activity
   - Blue bars: CPU activity
   - Text lines: Log messages

### 7.2 Radio Messages Window

Should show 3 UDP packets:

| Time | Source | Dest | Type | Size |
|------|--------|------|------|------|
| ~5s | Mote 2 | Mote 1 | 0x01 (AUTH) | ~6.5 KB |
| ~6s | Mote 1 | Mote 2 | 0x02 (ACK) | ~40 B |
| ~7s | Mote 2 | Mote 1 | 0x03 (DATA) | ~115 B |

### 7.3 Network Graph

In the **Network** panel:
- **Green arrows**: Successful packet delivery
- **Red arrows**: Failed/dropped packets (should be none with default settings)

---

## 🔧 Step 8: Customize & Experiment

### 8.1 Change Message Content

Edit `node-sender.c` line 52:
```c
static const char *secret_message = "Hello IoT";
```

Change to:
```c
static const char *secret_message = "Your Custom Message Here";
```

**Then rebuild**:
```powershell
make TARGET=z1
```

Reload firmware in Cooja.

### 8.2 Add More Sender Nodes

1. In Cooja: **Motes → Add motes**
2. Select **Z1 mote**
3. Choose `node-sender.z1` firmware
4. Add 2-3 more motes
5. All will try to authenticate with the gateway

Watch how the gateway handles multiple authentication requests!

### 8.3 Introduce Network Errors

In **Settings → Radio Medium**:
- Set **Success ratio TX**: 0.9 (10% packet loss)
- Set **Success ratio RX**: 0.9

Observe how the protocol handles retransmissions.

### 8.4 Adjust Ring Size

Edit `crypto_core.h` line 19:
```c
#define RING_SIZE 3
```

Change to:
```c
#define RING_SIZE 7  // More anonymity
```

**WARNING**: Rebuild required. Larger rings = longer computation time.

---

## 💾 Step 9: Save Your Simulation

### 9.1 Save Current State

**File → Save Simulation As...**

Save to:
```
C:\Users\aloob\Desktop\My_Research\my_simulation.csc
```

### 9.2 Enable Auto-Save

**Edit → Preferences → Auto-save**

Set interval: 60 seconds

---

## 📸 Step 10: Capture Results

### 10.1 Screenshot Mote Output

1. Right-click in **Mote Output** window
2. **Copy to clipboard** OR **Save to file**
3. Paste into your report/documentation

### 10.2 Export Timeline

1. In **Timeline** window: **File → Export to CSV**
2. Save for data analysis

### 10.3 Log to File

Before starting simulation:

1. **Tools → Script Editor**
2. Enter this script:
```javascript
TIMEOUT(600000); // 10 minutes

log.log("=== Simulation Started ===\n");

mote1 = sim.getMoteWithID(1);
mote2 = sim.getMoteWithID(2);

while(true) {
    YIELD();
    log.log(time + ": " + msg + "\n");
}
```
3. Click **Activate**
4. Logs will be saved automatically

---

## ❓ Troubleshooting

### Problem 1: Cooja Doesn't Start

**Error**: `ant: command not found`

**Solution**:
```powershell
# Install Apache Ant
choco install ant

# OR set PATH manually
$env:PATH += ";C:\apache-ant\bin"
```

### Problem 2: Firmware Path Not Found

**Error**: `Cannot find firmware file`

**Solution**:
1. Ensure you compiled with `make TARGET=z1`
2. Check path: `C:\Users\aloob\Desktop\My_Research\build\z1\*.z1`
3. In Cooja, click **Update paths** and browse manually

### Problem 3: Motes Don't Communicate

**Symptoms**: Sender starts, but gateway receives nothing

**Check**:
1. **Network panel**: Are motes **within 50m**?
2. **Radio Medium**: Is **UDGM** selected?
3. **Mote IDs**: Gateway should be ID=1, Sender ID=2
4. **Logs**: Look for `[INFO: IPv6 Route] Add default route`

**Fix**: Restart simulation or adjust positions

### Problem 4: Signature Verification Fails

**Error**: `*** SIGNATURE INVALID ***`

**Possible causes**:
1. Different PRNG seeds (sender/gateway using same addresses)
2. Parameter mismatch in `crypto_core.h`

**Fix**: Rebuild both firmwares:
```powershell
make clean TARGET=z1
make TARGET=z1
```

### Problem 5: LDPC Decoding Fails

**Error**: `Decryption failed!`

**Causes**:
1. Syndrome corrupted during transmission
2. LDPC decoder not converging

**Check**:
- Increase max iterations in `sldspa_decode()` (line 858 in `crypto_core.c`)
- Reduce error vector weight

### Problem 6: Simulation Too Slow

**Symptoms**: Z1 motes taking forever for polynomial operations

**Solution**:
1. **Simulation Control**: Set speed to **No speed limit**
2. **Or**: Close Timeline window (rendering is expensive)
3. **Or**: Use `native` target for faster testing

---

## 📊 Performance Monitoring

### Check Execution Time

In **Mote Output**, note timestamps:

```
0:00:05 [Gateway] Gateway Ready
0:00:10 [Sender] Ring signature generated
0:00:25 [Gateway] *** SIGNATURE VALID ***
0:00:30 [Gateway] *** DECRYPTED MESSAGE: Hello IoT ***
```

**Total protocol time**: ~25-30 seconds (Z1 simulation)

### Monitor Memory Usage

1. **Tools → Collect View**
2. Add column: **Heap memory usage**
3. Watch as cryptographic operations execute

---

## 🎯 Success Criteria Checklist

Your simulation is successful if you see:

- [x] Gateway initializes all cryptographic keys
- [x] Sender generates ring signature
- [x] `*** SIGNATURE VALID ***` appears in gateway logs
- [x] ACK packet sent with LDPC public key
- [x] Sender encrypts message
- [x] Gateway decodes LDPC syndrome
- [x] `*** DECRYPTED MESSAGE: Hello IoT ***` appears
- [x] `Protocol execution successful!` on both nodes

**If ALL checkboxes are checked**: 🎉 **PERFECT! Your post-quantum crypto is working!**

---

## 📚 Additional Resources

### Cooja Documentation
- Official guide: https://docs.contiki-ng.org/en/develop/doc/tutorials/Running-Contiki-NG-in-Cooja.html

### Our Project Documentation
- **README.md**: Project architecture
- **RUN_INSTRUCTIONS.md**: Command-line execution
- **RESULTS.md**: Expected performance metrics
- **SIMULATION_SUMMARY.md**: Build verification report

### Video Tutorial Suggestion

Record your screen while running the simulation:
1. Start with Cooja GUI
2. Load simulation
3. Run protocol
4. Show successful decryption
5. Explain each phase

---

## 🔄 Quick Reference Commands

### Compile
```powershell
cd C:\Users\aloob\Desktop\My_Research
make TARGET=z1
```

### Start Cooja
```powershell
cd C:\contiki-ng\tools\cooja
ant run
```

### Load Simulation
```
File → Open Simulation → simulation.csc
```

### Essential Windows
```
Tools → Mote Output (REQUIRED)
Tools → Timeline (Recommended)
Tools → Radio Messages (Optional)
```

### Run
```
Click Start button (or Ctrl+S)
```

---

**Created**: January 30, 2026  
**For**: Post-Quantum Cryptography IoT Simulation  
**Platform**: Contiki-NG Cooja Simulator  
**Status**: Ready to Run ✅
