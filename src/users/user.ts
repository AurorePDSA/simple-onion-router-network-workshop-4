import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import { error } from "console";
import { Node } from "../registry/registry";
import { createRandomSymmetricKey, exportSymKey, rsaEncrypt, symEncrypt } from "../crypto";


// Define the type for the body of the send message request
export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

// Function to create a user
export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  var lastReceivedMessage: string | null = null;
  var lastSentMessage: string | null = null;
  let getLastCircuit: Node[] = [];

  // Endpoint to check the status of the user
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Endpoint to get the last received message
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Endpoint to get the last sent message
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Endpoint for receiving messages
  _user.post("/message", (req, res) => {
    const receivedMessage = req.body.message;
    lastReceivedMessage = receivedMessage;
    res.status(200).send("success");
  });

  // Endpoint for sending messages
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;
    lastSentMessage = message;

    // Fetch the nodes
    const response = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
    const body = await response.json() as { nodes: Node[] };
    const nodes = body.nodes;

    // Shuffle the nodes
    nodes.sort(() => Math.random() - 0.5);

    // Create a circuit
    const circuit: Node[] = nodes.slice(0, 3);

    let destination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, "0");
    let payload = message;

    // Encrypt the payload
    for (const node of circuit) {
      const AESKey = await createRandomSymmetricKey();
      const encryptedPayload = await symEncrypt(AESKey, `${destination}${payload}`);
      const encryptedAESKey = await rsaEncrypt(await exportSymKey(AESKey), node.pubKey);

      destination = `${BASE_ONION_ROUTER_PORT + node.nodeId}`.padStart(10, "0");
      payload = encryptedAESKey + encryptedPayload;
    }

    // Reverse the circuit
    circuit.reverse();
    getLastCircuit = circuit;

    // Send the message
    await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + circuit[0].nodeId}/message`, {
      method: "POST",
      body: JSON.stringify({ message: payload }),
      headers: { "Content-Type": "application/json" },
    });

    res.status(200).send("success");
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.status(200).json({result: getLastCircuit.map((node) => node.nodeId)});
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}