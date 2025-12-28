using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace HydraDragonClient.Protocol
{
    /// <summary>
    /// Message types for the remote desktop protocol
    /// </summary>
    public enum MessageType : byte
    {
        ConnectRequest = 1,
        ConnectResponse = 2,
        ScreenFrame = 3,
        KeyboardInput = 4,
        MouseInput = 5,
        Disconnect = 6,
        Heartbeat = 7,
        FileTransferRequest = 8,
        FileChunk = 9
    }

    /// <summary>
    /// Base class for all protocol messages
    /// </summary>
    public abstract class ProtocolMessage
    {
        public abstract MessageType Type { get; }
        
        public byte[] Serialize()
        {
            var json = JsonSerializer.Serialize(this, this.GetType());
            var jsonBytes = Encoding.UTF8.GetBytes(json);
            
            // Format: [1 byte type][4 bytes length][json data]
            var result = new byte[5 + jsonBytes.Length];
            result[0] = (byte)Type;
            BitConverter.GetBytes(jsonBytes.Length).CopyTo(result, 1);
            jsonBytes.CopyTo(result, 5);
            
            return result;
        }

        public static ProtocolMessage? Deserialize(byte[] data)
        {
            if (data.Length < 5) return null;
            
            var type = (MessageType)data[0];
            var length = BitConverter.ToInt32(data, 1);
            
            if (data.Length < 5 + length) return null;
            
            var json = Encoding.UTF8.GetString(data, 5, length);
            
            return type switch
            {
                MessageType.ConnectRequest => JsonSerializer.Deserialize<ConnectRequest>(json),
                MessageType.ConnectResponse => JsonSerializer.Deserialize<ConnectResponse>(json),
                MessageType.ScreenFrame => JsonSerializer.Deserialize<ScreenFrame>(json),
                MessageType.KeyboardInput => JsonSerializer.Deserialize<KeyboardInput>(json),
                MessageType.MouseInput => JsonSerializer.Deserialize<MouseInput>(json),
                MessageType.Disconnect => JsonSerializer.Deserialize<DisconnectMessage>(json),
                MessageType.Heartbeat => JsonSerializer.Deserialize<Heartbeat>(json),
                MessageType.FileTransferRequest => JsonSerializer.Deserialize<FileTransferRequest>(json),
                MessageType.FileChunk => JsonSerializer.Deserialize<FileChunk>(json),
                _ => null
            };
        }
    }

    /// <summary>
    /// Connection request from client to remote
    /// </summary>
    public class ConnectRequest : ProtocolMessage
    {
        public override MessageType Type => MessageType.ConnectRequest;
        public string PasswordHash { get; set; } = "";
        public string ClientName { get; set; } = "";
    }

    /// <summary>
    /// Connection response from remote to client
    /// </summary>
    public class ConnectResponse : ProtocolMessage
    {
        public override MessageType Type => MessageType.ConnectResponse;
        public bool Accepted { get; set; }
        public string Reason { get; set; } = "";
        public int ScreenWidth { get; set; }
        public int ScreenHeight { get; set; }
    }

    /// <summary>
    /// Screen frame data (JPEG compressed)
    /// </summary>
    public class ScreenFrame : ProtocolMessage
    {
        public override MessageType Type => MessageType.ScreenFrame;
        public long Timestamp { get; set; }
        public string ImageBase64 { get; set; } = "";
    }

    /// <summary>
    /// Keyboard input event
    /// </summary>
    public class KeyboardInput : ProtocolMessage
    {
        public override MessageType Type => MessageType.KeyboardInput;
        public int VirtualKeyCode { get; set; }
        public bool IsKeyDown { get; set; }
        public bool Shift { get; set; }
        public bool Control { get; set; }
        public bool Alt { get; set; }
    }

    /// <summary>
    /// Mouse input event
    /// </summary>
    public class MouseInput : ProtocolMessage
    {
        public override MessageType Type => MessageType.MouseInput;
        public int X { get; set; }
        public int Y { get; set; }
        public MouseAction Action { get; set; }
        public int WheelDelta { get; set; }
    }

    public enum MouseAction : byte
    {
        Move = 0,
        LeftDown = 1,
        LeftUp = 2,
        RightDown = 3,
        RightUp = 4,
        MiddleDown = 5,
        MiddleUp = 6,
        Wheel = 7
    }

    /// <summary>
    /// Disconnect message
    /// </summary>
    public class DisconnectMessage : ProtocolMessage
    {
        public override MessageType Type => MessageType.Disconnect;
        public string Reason { get; set; } = "";
    }

    /// <summary>
    /// Heartbeat to keep connection alive
    /// </summary>
    public class Heartbeat : ProtocolMessage
    {
        public override MessageType Type => MessageType.Heartbeat;
        public long Timestamp { get; set; }
    }

    /// <summary>
    /// Request to start a file transfer
    /// </summary>
    public class FileTransferRequest : ProtocolMessage
    {
        public override MessageType Type => MessageType.FileTransferRequest;
        public string TransferId { get; set; } = "";
        public string FileName { get; set; } = "";
        public long FileSize { get; set; }
    }

    /// <summary>
    /// Chunk of file data
    /// </summary>
    public class FileChunk : ProtocolMessage
    {
        public override MessageType Type => MessageType.FileChunk;
        public string TransferId { get; set; } = "";
        public int Index { get; set; }
        public string DataBase64 { get; set; } = "";
        public bool IsLast { get; set; }
    }
}
