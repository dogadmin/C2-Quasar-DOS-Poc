#数据流：
```
→ AsyncReceive读取Header+Payload 
→ PayloadReader.ReadMessage() 
→ Serializer.Deserialize<IMessage>()  ← 认证前！
→ OnClientRead(message)
→ 检查client.Identified  ← 认证检查
```

问题代码
```
// Client.cs:365 - 认证前执行
_payloadLen = BitConverter.ToInt32(_payloadBuffer, _readOffset);
if (_payloadLen <= 0 || _payloadLen > MaxMessageSize)
    throw new Exception("invalid header");

// Client.cs:432-437 - 认证前执行
using (PayloadReader pr = new PayloadReader(_payloadBuffer, _payloadLen + HeaderSize, false))
{
    IMessage message = Serializer.Deserialize<IMessage>(_innerStream);  
    OnClientRead(message, _payloadBuffer.Length);
}
```

利用Protobuf在rsa认证前执行dos攻击，实现对C2进行部分干扰效果
