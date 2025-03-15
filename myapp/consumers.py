import json
from channels.generic.websocket import AsyncWebsocketConsumer

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """When a user connects to a WebSocket room"""
        self.room_name = self.scope["url_route"]["kwargs"]["room_name"]
        self.room_group_name = f"chat_{self.room_name}"

        # Add user to the room group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

        await self.accept()
        await self.send(text_data=json.dumps({"message": "Connected to the chat"}))

    async def disconnect(self, close_code):
        """When a user disconnects"""
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        """Receive messages from WebSocket"""
        try:
            data = json.loads(text_data)
            message = data.get("message", "")
            sender = data.get("sender", "")

            #  Broadcast message to the group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "chat_message",
                    "message": message,
                    "sender": sender,
                }
            )
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({"error": "Invalid JSON"}))

    async def chat_message(self, event):
        """Send message to WebSocket clients in the room"""
        await self.send(text_data=json.dumps({
            "message": event["message"],
            "sender": event["sender"],
        }))
