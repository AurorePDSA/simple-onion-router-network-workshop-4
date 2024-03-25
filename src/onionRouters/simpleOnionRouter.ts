import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPrvKey, exportPubKey, rsaDecrypt, symDecrypt, importPrvKey } from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // Generate RSA key pair
  const keyPair = await generateRsaKeyPair();
  const publicKey = await exportPubKey(keyPair.publicKey);
  const privateKey = await exportPrvKey(keyPair.privateKey);

  let lastReceivedEncryptedMessage: any = null;
  let lastReceivedDecryptedMessage: any = null;
  let lastMessageDestination: number | null = null;
  let lastSentMessage: any = null;

  // Register node on the registry
  const registryUrl = `http://localhost:${REGISTRY_PORT}/registerNode`;
  const response = await fetch(registryUrl, {
    method: "POST",
    body: JSON.stringify({
      nodeId: nodeId,
      pubKey: publicKey,
    }),
    headers: { "Content-Type": "application/json" },
  });

  // Endpoint to check if the server is live
  onionRouter.get("/status", (req, res) => {
    res.send('live');
  });

  // Endpoint to get the last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Endpoint to get the last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Endpoint to get the last message destination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Endpoint to get the last sent message
  onionRouter.get("/getLastSentMessage", (req, res) => {
    if (lastSentMessage === null) {
      res.json({ result: null });
    } else {
      res.json({ result: lastSentMessage });
    }
  });

  // GET /getPrivateKey
  onionRouter.get("/getPrivateKey", async (req, res) => {
    res.json({ result: privateKey });
  });

  // Endpoint to receive and process messages
  onionRouter.post("/message", async (req, res) => {
    // Extract the message layer from the request body
    const layer = req.body.message;

    // Decrypt the AES key using the private key
    const AESKey = privateKey ? await rsaDecrypt(layer.slice(0, 344), await importPrvKey(privateKey)) : null;

    // Decrypt the payload using the AES key
    const payload = AESKey ? await symDecrypt(AESKey, layer.slice(344)) : null;

    // Store the last received encrypted and decrypted messages
    lastReceivedEncryptedMessage = layer;
    lastReceivedDecryptedMessage = payload ? payload.slice(10) : null;

    // Extract and store the destination of the last message
    lastMessageDestination = payload ? parseInt(payload.slice(0, 10), 10) : null;

    // If a destination is specified, forward the decrypted message to the destination
    if (lastMessageDestination) {
      await fetch(`http://localhost:${lastMessageDestination}/message`, {
        method: "POST",
        body: JSON.stringify({ message: lastReceivedDecryptedMessage }),
        headers: { "Content-Type": "application/json" },
      });
    }

    // Respond with a success status
    res.status(200).send({ result: "Success" });
  });


  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
