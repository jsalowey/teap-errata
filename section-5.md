
### 5.  Cryptographic Calculations

   For key derivation and crypto-binding, TEAP uses the Pseudorandom
   Function (PRF) and MAC algorithms negotiated in the underlying TLS
   session.  Since these algorithms depend on the TLS version and
   ciphersuite, TEAP implementations need a mechanism to determine the
   version and ciphersuite in use for a particular session.  The
   implementation can then use this information to determine which PRF
   and MAC algorithm to use.

### 5.1.  TEAP Authentication Phase 1: Key Derivations

   With TEAPv1, the TLS master secret is generated as specified in TLS.
   If a PAC is used, then the master secret is obtained as described in
   [RFC5077].

   TEAPv1 makes use of the TLS Keying Material Exporters defined in
   [RFC5705] to derive the session_key_seed.  The label used in the
   derivation is "EXPORTER: teap session key seed".  The length of the
   session key seed material is 40 octets.  No context data is used in
   the export process.

   The session_key_seed is used by the TEAP authentication Phase 2
   conversation to both cryptographically bind the inner method(s) to
   the tunnel as well as generate the resulting TEAP session keys.  The
   other TLS keying materials are derived and used as defined in
   [RFC5246].

### 5.2.  Intermediate Compound Key Derivations

   The session_key_seed derived as part of TEAP Phase 2 is used in TEAP
   Phase 2 to generate an Intermediate Compound Key (IMCK) used to
   verify the integrity of the TLS tunnel after each successful inner
   authentication and in the generation of Master Session Key (MSK) and
   Extended Master Session Key (EMSK) defined in [RFC3748].  Note that
   the IMCK MUST be recalculated after each successful inner EAP method.

   The first step in these calculations is the generation of the base
   compound key, IMCK[n] from the session_key_seed, and any session keys
   derived from the successful execution of nth inner EAP methods.  The
   inner EAP method(s) may provide Inner Method Session Keys (IMSKs),
   IMSK1..IMSKn, corresponding to inner method 1 through n.

   If an inner method supports export of an Extended Master Session Key
   (EMSK), then the IMSK SHOULD be derived from the EMSK as defined in
   [RFC5295].  The usage label used is "TEAPbindkey@ietf.org", and the
   length is 64 octets.  Optional data parameter is not used in the
   derivation.
      
     IMSK = First 32 octets of TLS-PRF(EMSK, "TEAPbindkey@ietf.org".org",
        0x00 | 0x00 | 0x40)

     where "|" denotes concatenation and the TLS-PRF is defined in
     [RFC5246] as

       TLS-PRF(secret, label, seed) = P_<hash>(secret, label | seed)

     The secret is the EMSK from the inner method, the label is
     "TEAPbindkey@ietf.org" consisting of the ASCII value for the
     label "TEAPbindkey@ietf.org" (without quotes),  the seed
     consists of the "\0" null delimiter (0x00) and 2-octet unsigned
     integer length in network byte order (0x00 | 0x4) specified
     in [RFC5295].

   If an inner method does not support export of an Extended Master
   Session Key (EMSK), then IMSK is the MSK of the inner method.  The
   MSK is truncated at 32 octets if it is longer than 32 octets or
   padded to a length of 32 octets with zeros if it is less than 32
   octets.

   However, it's possible that the peer and server sides might not have
   the same capability to export EMSK.  In order to maintain maximum
   flexibility while prevent downgrading attack, the following mechanism
   is in place.

   On the sender of the Crypto-Binding TLV side:

     If the EMSK is not available, then the sender computes the Compound
     MAC using the MSK of the inner method.

     If the EMSK is available and the sender's policy accepts MSK-based
     MAC, then the sender computes two Compound MAC values.  The first
     is computed with the EMSK.  The second one is computed using the
     MSK.  Both MACs are then sent to the other side.

     If the EMSK is available but the sender's policy does not allow
     downgrading to MSK-generated MAC, then the sender SHOULD only send
     EMSK-based MAC.

   On the receiver of the Crypto-Binding TLV side:

     If the EMSK is not available and an MSK-based Compound MAC was
     sent, then the receiver validates the Compound MAC and sends back
     an MSK-based Compound MAC response.

     If the EMSK is not available and no MSK-based Compound MAC was
     sent, then the receiver handles like an invalid Crypto-Binding TLV
     with a fatal error.

     If the EMSK is available and an EMSK-based Compound MAC was sent,
     then the receiver validates it and creates a response Compound MAC
     using the EMSK.

     If the EMSK is available but no EMSK-based Compound MAC was sent
     and its policy accepts MSK-based MAC, then the receiver validates
     it using the MSK and, if successful, generates and returns an MSK-
     based Compound MAC.

     If the EMSK is available but no EMSK Compound MAC was sent and its
     policy does not accept MSK-based MAC, then the receiver handles
     like an invalid Crypto-Binding TLV with a fatal error.

   If the ith inner method does not generate an EMSK or MSK, then IMSKi
   is set to zero (e.g., MSKi = 32 octets of 0x00s).  If an inner method
   fails, then it is not included in this calculation.  The derivation
   of S-IMCK is as follows:

      S-IMCK[0] = session_key_seed
      For j = 1 to n-1 do
           IMCK[j] = the first 60 bytes of TLS-PRF(S-IMCK[j-1], 
           "Inner Methods Compound Keys", IMSK[j])

      where "|" denotes concatenation and the TLS-PRF is defined in
      [RFC5246] as

        TLS-PRF(secret, label, seed) = P_<hash>(secret, label | seed).

      the secret is S-IMCK[j-1], the label is 
      "Inner Methods Compound Keys" consisting of the ASCII value for 
      the label "Inner Methods Compound Keys" (without quotes), the 
      seed consists IMSK[j]. The secret is S-IMCK[j-1]  where j is 
      the number of the last successfully executed inner EAP method.  .

      S-IMCK[j] = first 40 octets of IMCK[j]
      CMK[j] = last 20 octets of IMCK[j]

   where TLS-PRF is the PRF negotiated as part of TLS handshake
   [RFC5246].

### 5.3.  Computing the Compound MAC

   For authentication methods that generate keying material, further
   protection against man-in-the-middle attacks is provided through
   cryptographically binding keying material established by both TEAP
   Phase 1 and TEAP Phase 2 conversations.  After each successful inner
   EAP authentication, EAP EMSK and/or MSKs are cryptographically
   combined with key material from TEAP Phase 1 to generate a Compound
   Session Key (CMK).  The CMK is used to calculate the Compound MAC as
   part of the Crypto-Binding TLV described in Section 4.2.13, which
   helps provide assurance that the same entities are involved in all
   communications in TEAP.  During the calculation of the Compound MAC,
   the MAC field is filled with zeros.

   The Compound MAC computation is as follows:

      CMK = CMK[j]
      Compound-MAC = MAC( CMK, BUFFER )

   where j is the number of the last successfully executed inner EAP
   method, MAC is HMAC [RFC2104] using the hash function negotiated in
   TLS [RFC5246].  The output length is the length of the output of the HMAC
   function.  The BUFFER is created after concatenating these fields in
   the following order:

   1  The entire Crypto-Binding TLV attribute with both the EMSK and MSK
      Compound MAC fields zeroed out.

   2  The EAP Type sent by the other party in the first TEAP message. This
       is a single octet encoded as (0x37)

   3  All the Outer TLVs from the first TEAP message sent by EAP server
      to peer.  If a single TEAP message is fragmented into multiple
      TEAP packets, then the Outer TLVs in all the fragments of that
      message MUST be included.

   4  All the Outer TLVs from the first TEAP message sent by the peer to
      the EAP server.  If a single TEAP message is fragmented into
      multiple TEAP packets, then the Outer TLVs in all the fragments of
      that message MUST be included.

### 5.4.  EAP Master Session Key Generation

   TEAP authentication assures the Master Session Key (MSK) and Extended
   Master Session Key (EMSK) output from the EAP method are the result
   of all authentication conversations by generating an Intermediate
   Compound Key (IMCK).  The IMCK is mutually derived by the peer and
   the server as described in Section 5.2 by combining the MSKs from
   inner EAP methods with key material from TEAP Phase 1.  The resulting
   MSK and EMSK are generated as part of the IMCKn key hierarchy as
   follows:


        MSK = the first 64 bytes of TLS-PRF(S-IMCK[j], 
           "Session Key Generating Function")
        EMSK = the first 64 bytes of TLS-PRF(S-IMCK[j], 
           "Extended Session Key Generating Function")

     where "|" denotes concatenation and the TLS-PRF is defined in
     [RFC5246] as

        PRF(secret, label, seed) = P_<hash>(secret, label | seed).

     where j is the number of the last successfully executed inner EAP
     method. The label is is the ASCII value for the string without quotes.  
     The seed is empty (0 length) and omitted from the derivation

   The EMSK is typically only known to the TEAP peer and server and is
   not provided to a third party.  The derivation of additional keys and
   transportation of these keys to a third party are outside the scope
   of this document.

   If no EAP methods have been negotiated inside the tunnel or no EAP
   methods have been successfully completed inside the tunnel, the MSK
   and EMSK will be generated directly from the session_key_seed meaning
   S-IMCK = session_key_seed.
