<?xml version="1.0" encoding="UTF-8"?>
<simconf>
  <project EXPORT="discard">[APPS_DIR]/mrm</project>
  <project EXPORT="discard">[APPS_DIR]/mspsim</project>
  <project EXPORT="discard">[APPS_DIR]/avrora</project>
  <project EXPORT="discard">[APPS_DIR]/serial_socket</project>
  <project EXPORT="discard">[APPS_DIR]/powertracker</project>
  
  <simulation>
    <title>Post-Quantum Crypto: LR-IoTA + QC-LDPC</title>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>gateway1</identifier>
      <description>Gateway Node - Post-Quantum Receiver</description>
      <source EXPORT="discard">[CONFIG_DIR]/node-gateway.c</source>
      <commands EXPORT="discard">make node-gateway.z1 TARGET=z1</commands>
      <firmware EXPORT="copy">[CONFIG_DIR]/node-gateway.z1</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspButton</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspLED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
    </motetype>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>sender1</identifier>
      <description>Sender Node - Post-Quantum Initiator</description>
      <source EXPORT="discard">[CONFIG_DIR]/node-sender.c</source>
      <commands EXPORT="discard">make node-sender.z1 TARGET=z1</commands>
      <firmware EXPORT="copy">[CONFIG_DIR]/node-sender.z1</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspButton</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspLED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
    </motetype>
    
    <!-- Gateway Mote (Network Coordinator) -->
    <mote>
      <breakpoints />
      <interface_config>
        org.contikios.cooja.interfaces.Position
        <x>0.0</x>
        <y>0.0</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        org.contikios.cooja.mspmote.interfaces.MspMoteID
        <id>1</id>
      </interface_config>
      <motetype_identifier>gateway1</motetype_identifier>
    </mote>
    
    <!-- Sender Mote -->
    <mote>
      <breakpoints />
      <interface_config>
        org.contikios.cooja.interfaces.Position
        <x>30.0</x>
        <y>0.0</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        org.contikios.cooja.mspmote.interfaces.MspMoteID
        <id>2</id>
      </interface_config>
      <motetype_identifier>sender1</motetype_identifier>
    </mote>
  </simulation>
  
  <!-- Plugins for visualization -->
  <plugin>
    org.contikios.cooja.plugins.SimControl
    <width>280</width>
    <z>0</z>
    <height>160</height>
    <location_x>0</location_x>
    <location_y>0</location_y>
  </plugin>
  
  <plugin>
    org.contikios.cooja.plugins.Visualizer
    <plugin_config>
      <moterelations>true</moterelations>
      <skin>org.contikios.cooja.plugins.skins.IDVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.GridVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.TrafficVisualizerSkin</skin>
      <skin>org.contikios.cooja.plugins.skins.UDGMVisualizerSkin</skin>
      <viewport>2.5 0.0 0.0 2.5 100.0 100.0</viewport>
    </plugin_config>
    <width>400</width>
    <z>1</z>
    <height>400</height>
    <location_x>280</location_x>
    <location_y>0</location_y>
  </plugin>
  
  <plugin>
    org.contikios.cooja.plugins.LogListener
    <plugin_config>
      <filter>Gateway|Sender|AUTH|LDPC|Decrypted</filter>
      <formatted_time />
      <coloring />
    </plugin_config>
    <width>1200</width>
    <z>2</z>
    <height>400</height>
    <location_x>0</location_x>
    <location_y>400</location_y>
  </plugin>
  
  <plugin>
    org.contikios.cooja.plugins.TimeLine
    <plugin_config>
      <mote>0</mote>
      <mote>1</mote>
      <showRadioRXTX />
      <showRadioHW />
      <showLEDs />
      <zoomfactor>500.0</zoomfactor>
    </plugin_config>
    <width>1200</width>
    <z>3</z>
    <height>200</height>
    <location_x>0</location_x>
    <location_y>800</location_y>
  </plugin>
  
  <plugin>
    org.contikios.cooja.plugins.Notes
    <plugin_config>
      <notes>Post-Quantum Cryptography Simulation
================================
1. Gateway (Mote 1): Receives and verifies Ring-LWE signatures
2. Sender (Mote 2): Generates signatures and encrypts data

Protocol Flow:
- Authentication Phase: Ring-LWE signature (N=3 members)
- ACK with LDPC Public Key
- Data Phase: LDPC+AES hybrid encryption

Watch the log output for:
- "SIGNATURE VALID" - authentication success
- "DECRYPTED MESSAGE" - successful end-to-end encryption

Parameters:
- Polynomial degree: 512
- Modulus q: 2^29-3
- LDPC: 408x816 matrix
- Ring size: 3 members</notes>
      <decorations>true</decorations>
    </plugin_config>
    <width>400</width>
    <z>4</z>
    <height>200</height>
    <location_x>680</location_x>
    <location_y>0</location_y>
  </plugin>
  
</simconf>
