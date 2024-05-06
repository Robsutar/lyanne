# Server/Client Handshake

1. **Client Initiation:**
   - The client sends an authentication/login message to the server.

2. **Server Response:**
   - If the server rejects the message, it sends a response detailing the reason for refusal, except in cases where the message is considered an attack.
   - If the server accepts the message, it sends a confirmation back to the client, indicating that the connection can be established. The client then sends a final confirmation message to the server.

# Communication While Client is Connected to Server

- **Server Tick:**
  - The server sends a "tick" to the client, containing all messages accumulated during the server tick in a single packet.

- **Client Response:**
  - The client sends its accumulated packets in a single packet to the server only after receiving the server tick. This also serves as confirmation that the previous packet was received successfully.

- **Packet Loss Handling:**
  - If the client does not respond within a designated time period (T), the server assumes packet loss occurred and resends the cached packet.

- **Packet Resending Rules:**
  - The server must wait for confirmation of the previous packet before sending the next tick. This may require the server to cache multiple ticks per player. If the client fails to respond within a reasonable time, the server clears its cache and terminates the connection.

# Server Tick Management

- **Packets Storage and Sending:**
  - The server may accumulate packets to be sent to the client at the next server tick. Packets are either sent immediately or stored for the next tick, depending on whether there are outstanding packets yet to be received by the client.

- **Handling Multiple Clients:**
  - The server can handle sending packets to any client at any time. However, actual transmission or storage for future transmission only occurs at the server tick.
