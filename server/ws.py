from fastapi import FastAPI
import websockets

app = FastAPI()

# define a WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: websockets.WebSocketServerProtocol):
    # get the user id and username from the query string
    user_id = websocket.query_params.get("userId")
    username = websocket.query_params.get("username")

    # handle incoming messages
    async for message in websocket:
        message_data = json.loads(message)
        recipient = message_data.get("recipient")
        text = message_data.get("text")
        if recipient and text:
            # send message to recipient
            # you will need to define a function to get the WebSocket instance for the recipient based on their user id
            recipient_websocket = get_websocket_by_user_id(recipient)
            await recipient_websocket.send(json.dumps({"text": text}))

    # handle connection close
    # you will need to define a function to remove the WebSocket instance from the list of connected clients
    remove_websocket(websocket)
